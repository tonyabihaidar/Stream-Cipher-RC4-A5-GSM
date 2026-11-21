// Explicit allowlist: never copy a request, plaintext, key, or keystream into history.
export function historyRecord(source) {
  if (!source || source.record_type !== 'eece455.stream-cipher.ciphertext' ||
      !['rc4', 'a51'].includes(source.algorithm) || source.encoding !== 'hex' ||
      typeof source.ciphertext !== 'string' || !/^(?:[0-9A-F]{2})+$/.test(source.ciphertext) ||
      source.ciphertext.length > 32768 || !Number.isInteger(source.bit_length) ||
      source.bit_length < 1 || Math.ceil(source.bit_length / 8) * 2 !== source.ciphertext.length) {
    throw new Error('This encryption record is invalid.');
  }
  const fields = ['record_type', 'version', 'algorithm', 'encoding', 'ciphertext', 'bit_length'];
  if (source.version !== 1) throw new Error('Unsupported record version.');
  if (source.algorithm === 'rc4') {
    if (!['text', 'hex'].includes(source.key_encoding) || source.bit_length % 8) throw new Error('Invalid RC4 record.');
    fields.push('key_encoding');
  } else {
    if (!['downlink', 'uplink'].includes(source.direction) || !['count', 'fn'].includes(source.count_mode) ||
        !Number.isInteger(source.start_count) || source.start_count < 0 || source.start_count > 4194303 ||
        (source.count_mode === 'fn' && (!Number.isInteger(source.start_fn) || source.start_fn < 0 || source.start_fn > 2715647)) ||
        (source.count_mode === 'count' && source.start_fn !== null) ||
        source.count_advance !== (source.count_mode === 'fn' ? 'FN + 1 mod 2715648' : 'COUNT + 1 mod 2^22') ||
        source.segment_count !== Math.ceil(source.bit_length / 114)) throw new Error('Invalid A5/1 record.');
    fields.push('direction', 'count_mode', 'start_count', 'start_fn', 'segment_count', 'count_advance');
  }
  return Object.fromEntries(fields.map((field) => [field, source[field]]));
}
