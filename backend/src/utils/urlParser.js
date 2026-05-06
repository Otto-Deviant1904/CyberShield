const validator = require('validator');

/**
 * Normalizes and validates the URL
 */
const normalizeUrl = (input) => {
  if (!input) return null;
  
  let url = input.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  try {
    const parsed = new URL(url);
    return parsed.toString();
  } catch (e) {
    return null;
  }
};

/**
 * Calculates Shannon entropy of a string
 */
const calculateEntropy = (str) => {
  const len = str.length;
  const frequencies = Array.from(str).reduce((acc, char) => {
    acc[char] = (acc[char] || 0) + 1;
    return acc;
  }, {});

  return Object.values(frequencies).reduce((acc, freq) => {
    const p = freq / len;
    return acc - p * Math.log2(p);
  }, 0);
};

module.exports = {
  normalizeUrl,
  calculateEntropy
};
