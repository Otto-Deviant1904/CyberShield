const test = require('node:test');
const assert = require('node:assert/strict');

const {
  isIpHost,
  isPrivateOrLocalHost,
  getSubdomainCount,
  getTld
} = require('../utils/urlUtils');

test('isIpHost accepts valid IPv4 and rejects invalid ranges', () => {
  assert.equal(isIpHost('192.168.1.1'), true);
  assert.equal(isIpHost('255.255.255.255'), true);
  assert.equal(isIpHost('256.1.1.1'), false);
  assert.equal(isIpHost('999.999.999.999'), false);
});

test('isPrivateOrLocalHost blocks local and private targets', () => {
  assert.equal(isPrivateOrLocalHost('localhost'), true);
  assert.equal(isPrivateOrLocalHost('127.0.0.1'), true);
  assert.equal(isPrivateOrLocalHost('10.0.0.25'), true);
  assert.equal(isPrivateOrLocalHost('172.20.10.9'), true);
  assert.equal(isPrivateOrLocalHost('192.168.5.44'), true);
  assert.equal(isPrivateOrLocalHost('169.254.7.12'), true);
  assert.equal(isPrivateOrLocalHost('example.com'), false);
});

test('getSubdomainCount skips IP hosts', () => {
  assert.equal(getSubdomainCount('127.0.0.1'), 0);
  assert.equal(getSubdomainCount('a.b.example.com'), 2);
});

test('getTld returns empty string for IP hosts', () => {
  assert.equal(getTld('127.0.0.1'), '');
  assert.equal(getTld('example.xyz'), 'xyz');
});
