// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
//
// Dependency-free regression for the tenant selector embedded in `/activate`.
// The Rust test passes the exact ACTIVATE_HTML bytes on stdin so this exercises
// shipped JavaScript rather than a copied implementation.

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync(0, 'utf8');
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert(scriptMatch, 'ACTIVATE_HTML must contain one inline script');
const script = scriptMatch[1].replace(/\nloadTenants\(\);\s*$/, '\n');

let innerHTMLWrites = 0;

class MockClassList {
  constructor() {
    this.values = new Set();
  }

  add(value) {
    this.values.add(value);
  }

  toggle(value, force) {
    if (force) this.values.add(value);
    else this.values.delete(value);
  }

  contains(value) {
    return this.values.has(value);
  }
}

class MockElement {
  constructor(tagName, id = '') {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.children = [];
    this.classList = new MockClassList();
    this.dataset = {};
    this.style = {};
    this.textContent = '';
    this.disabled = false;
    this.selected = false;
    this.focused = false;
    this._value = '';
  }

  set innerHTML(_value) {
    innerHTMLWrites += 1;
    throw new Error('innerHTML is forbidden in the /activate tenant selector');
  }

  get innerHTML() {
    return '';
  }

  get value() {
    return this._value;
  }

  set value(value) {
    this._value = String(value);
    if (this.tagName === 'SELECT') {
      let matched = false;
      this.children.forEach((child) => {
        child.selected = !matched && child.value === this._value;
        matched = matched || child.selected;
      });
    }
  }

  get options() {
    return this.children;
  }

  get selectedIndex() {
    return this.children.findIndex((child) => child.selected);
  }

  set selectedIndex(index) {
    this.children.forEach((child, childIndex) => {
      child.selected = childIndex === index;
    });
    this._value = index >= 0 && index < this.children.length
      ? this.children[index].value
      : '';
  }

  appendChild(child) {
    assert.equal(child.tagName, 'OPTION', 'tenant selector may append only OPTION nodes');
    this.children.push(child);
    if (this.children.length === 1) {
      child.selected = true;
      this._value = child.value;
    } else if (child.selected) {
      this.children.forEach((option) => {
        option.selected = option === child;
      });
      this._value = child.value;
    }
    return child;
  }

  replaceChildren(...children) {
    this.children = [];
    this._value = '';
    children.forEach((child) => this.appendChild(child));
  }

  focus() {
    this.focused = true;
  }
}

const elements = new Map([
  ['tenant_sel', new MockElement('select', 'tenant_sel')],
  ['newrow', new MockElement('div', 'newrow')],
  ['tenant_new', new MockElement('input', 'tenant_new')],
  ['form', new MockElement('form', 'form')],
  ['signin', new MockElement('div', 'signin')],
  ['signin_link', new MockElement('a', 'signin_link')],
]);
const created = [];
const document = {
  createElement(tagName) {
    const node = new MockElement(tagName);
    created.push(node);
    return node;
  },
  getElementById(id) {
    return elements.get(id);
  },
  querySelectorAll() {
    return [];
  },
};

const context = vm.createContext({
  console,
  document,
  encodeURIComponent,
  location: { href: 'https://crux.example/activate' },
  fetch: () => new Promise(() => {}),
});
vm.runInContext(script, context, { filename: 'ACTIVATE_HTML:inline-script' });

async function load(payload) {
  context.fetch = async () => ({
    headers: { get: () => 'application/json; charset=utf-8' },
    redirected: false,
    ok: true,
    json: async () => payload,
  });
  await vm.runInContext('loadTenants()', context);
  return elements.get('tenant_sel');
}

function assertOptions(select, expectedValues) {
  assert.equal(select.children.length, expectedValues.length + 1);
  expectedValues.forEach((expected, index) => {
    const option = select.children[index];
    assert.equal(option.tagName, 'OPTION');
    assert.equal(option.value, expected);
    assert.equal(option.textContent, expected);
    assert.equal(option.disabled, false);
    assert.equal(option.selected, index === 0);
    assert.equal(option.dataset.tenantAction, undefined);
    assert.deepEqual(option.children, []);
  });
  const addNew = select.children.at(-1);
  assert.equal(addNew.tagName, 'OPTION');
  assert.equal(addNew.value, '__add_new__');
  assert.equal(addNew.textContent, '+ Add new tenant…');
  assert.equal(addNew.disabled, false);
  assert.equal(addNew.dataset.tenantAction, 'add');
}

(async () => {
  const hostile = [
    '</option><option autofocus onfocus="globalThis.__pwned=1">',
    '<img src=x onerror="globalThis.__pwned=2">',
    'quotes: "double" and \'single\' & ampersand',
    'tenant-雪-🛡️',
    '__add_new__',
  ];

  let select = await load({ tenants: hostile.map((tenant_id) => ({ tenant_id })) });
  assertOptions(select, hostile);
  assert.equal(innerHTMLWrites, 0);
  assert.equal(context.__pwned, undefined);
  hostile.forEach((tenant, index) => {
    select.selectedIndex = index;
    assert.equal(vm.runInContext('currentTenant()', context), tenant);
  });
  select.selectedIndex = hostile.indexOf('__add_new__');
  vm.runInContext('onTenantChange()', context);
  assert(!elements.get('newrow').classList.contains('show'));

  const legacy = ['legacy-<b>literal</b>', 'legacy-&-雪'];
  select = await load(legacy);
  assertOptions(select, legacy);
  assert.equal(innerHTMLWrites, 0);

  select = await load({ tenants: [] });
  assert.equal(select.children.length, 2);
  const placeholder = select.children[0];
  assert.equal(placeholder.tagName, 'OPTION');
  assert.equal(placeholder.value, '');
  assert.equal(placeholder.textContent, 'No tenants yet — add one');
  assert.equal(placeholder.disabled, true);
  assert.equal(placeholder.selected, true);
  assert.equal(select.children[1].value, '__add_new__');

  select.selectedIndex = select.children.length - 1;
  vm.runInContext('onTenantChange()', context);
  assert(elements.get('newrow').classList.contains('show'));
  assert(elements.get('tenant_new').focused);
  elements.get('tenant_new').value = '  new-tenant  ';
  assert.equal(vm.runInContext('currentTenant()', context), 'new-tenant');

  assert(created.every((node) => node.tagName === 'OPTION'));
  assert.equal(innerHTMLWrites, 0);
  assert.equal(context.__pwned, undefined);
  console.log('activate tenant DOM smoke: PASS');
})().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
