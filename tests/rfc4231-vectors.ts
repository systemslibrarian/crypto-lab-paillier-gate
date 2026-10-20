/*
 * RFC 4231 HMAC-SHA-256 test vectors — copied from the publication.
 *
 * Source: https://www.rfc-editor.org/rfc/rfc4231.txt
 *   sha256 72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b
 *   Sections 4.2 through 4.8, the HMAC-SHA-256 line of each of the seven cases.
 *
 * COPIED FROM THE PUBLICATION, not regenerated. A vector produced by WebCrypto, or by
 * any library, agrees with the code for the same reason it agrees with itself.
 *
 * The extraction was checked against the RFC's own "(N bytes)" annotations rather than
 * trusted, and that caught a real miss: Test Case 3 writes its key as `Key` with NO
 * equals sign, alone among the seven, so a reader keyed on `Key =` silently produced a
 * ZERO-length key for it. The RFC's stated 20 bytes is what exposed it. Every case's
 * key, data and MAC length now matches the count the RFC states beside it.
 *
 * Case 5 has a 16-byte MAC on purpose: section 4.6 truncates the output to 128 bits.
 * It is kept because a verifier that compared only a prefix would pass the other six.
 */

export interface HmacVector {
  readonly name: string;
  readonly keyHex: string;
  readonly dataHex: string;
  readonly macHex: string;
}

export const RFC4231_HMAC_SHA256: readonly HmacVector[] = [
  {
    name: 'RFC 4231 Test Case 1 — 20-byte key, 8-byte data',
    keyHex:
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b' +
      '0b0b0b0b',
    dataHex:
      '4869205468657265',
    macHex:
      'b0344c61d8db38535ca8afceaf0bf12b' +
      '881dc200c9833da726e9376c2e32cff7',
  },
  {
    name: 'RFC 4231 Test Case 2 — short key, "what do ya want for nothing?"',
    keyHex:
      '4a656665',
    dataHex:
      '7768617420646f2079612077616e7420' +
      '666f72206e6f7468696e673f',
    macHex:
      '5bdcc146bf60754e6a042426089575c7' +
      '5a003f089d2739839dec58b964ec3843',
  },
  {
    name: 'RFC 4231 Test Case 3 — key plus data longer than the 64-byte SHA-256 block',
    keyHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaa',
    dataHex:
      'dddddddddddddddddddddddddddddddd' +
      'dddddddddddddddddddddddddddddddd' +
      'dddddddddddddddddddddddddddddddd' +
      'dddd',
    macHex:
      '773ea91e36800e46854db8ebd09181a7' +
      '2959098b3ef8c122d9635514ced565fe',
  },
  {
    name: 'RFC 4231 Test Case 4 — a 25-byte key of ascending bytes',
    keyHex:
      '0102030405060708090a0b0c0d0e0f10' +
      '111213141516171819',
    dataHex:
      'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
      'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
      'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
      'cdcd',
    macHex:
      '82558a389a443c0ea4cc819899f2083a' +
      '85f0faa3e578f8077a2e3ff46729665b',
  },
  {
    name: 'RFC 4231 Test Case 5 — output truncated to 128 bits -- RFC 4231 section 4.6, so the tag is 16 bytes',
    keyHex:
      '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c' +
      '0c0c0c0c',
    dataHex:
      '546573742057697468205472756e6361' +
      '74696f6e',
    macHex:
      'a3b6167473100ee06e0c796c2955552b',
  },
  {
    name: 'RFC 4231 Test Case 6 — a 131-byte key, longer than the block, so it is hashed first',
    keyHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaa',
    dataHex:
      '54657374205573696e67204c61726765' +
      '72205468616e20426c6f636b2d53697a' +
      '65204b6579202d2048617368204b6579' +
      '204669727374',
    macHex:
      '60e431591ee0b67f0d8a26aacbf5b77f' +
      '8e0bc6213728c5140546040f0ee37f54',
  },
  {
    name: 'RFC 4231 Test Case 7 — a 131-byte key with 152 bytes of data',
    keyHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaa',
    dataHex:
      '54686973206973206120746573742075' +
      '73696e672061206c6172676572207468' +
      '616e20626c6f636b2d73697a65206b65' +
      '7920616e642061206c61726765722074' +
      '68616e20626c6f636b2d73697a652064' +
      '6174612e20546865206b6579206e6565' +
      '647320746f2062652068617368656420' +
      '6265666f7265206265696e6720757365' +
      '642062792074686520484d414320616c' +
      '676f726974686d2e',
    macHex:
      '9b09ffa71b942fcb27635fbcd5b0e944' +
      'bfdc63644f0713938a7f51535c3a35e2',
  },
];
