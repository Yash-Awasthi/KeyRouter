// Workers-only APIs that the DOM lib does not describe. Only what this worker calls.
interface SubtleCrypto {
  /** Present in the Workers runtime; compares two buffers in constant time. */
  timingSafeEqual(a: ArrayBufferView, b: ArrayBufferView): boolean;
}
