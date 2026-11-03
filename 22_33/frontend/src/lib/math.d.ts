export interface Point {
  x: string;
  y: string;
}
export interface ScalarRound {
  bit: number;
  selected: number;
  accumulator: string[];
  nextDouble: string[];
}
export interface SignatureTrace {
  seed: string;
  message: string;
  expanded: string;
  clamped: string;
  prefix: string;
  a: string;
  publicKey: string;
  A: Point;
  nonceInput: string;
  nonceHash: string;
  r: string;
  R: Point;
  encodedR: string;
  challengeInput: string;
  challengeHash: string;
  k: string;
  s: string;
  encodedS: string;
  signature: string;
  signatureBase64: string;
  lhs: Point;
  rhs: Point;
  matches: boolean;
  nativeVerified: boolean;
  equal: boolean;
  constants: { p: string; L: string; d: string; B: Point };
  traces: Record<string, ScalarRound[]>;
}
export function traceSignature(
  seed: Uint8Array,
  message: Uint8Array,
  includeTrace?: boolean,
): Promise<SignatureTrace>;
export function payload(
  sender: string,
  recipient: string,
  content: string,
  nonce?: string,
): string;
export function hex(bytes: Uint8Array): string;
export function fromHex(value: string): Uint8Array;
