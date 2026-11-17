// Loads presign.wasm and exposes analyze(request) -> {ok: report} | {error}.
export async function loadPresign(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const { memory, presign_alloc, presign_free, presign_analyze } = instance.exports;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  return {
    analyze(request) {
      const input = enc.encode(JSON.stringify(request));
      const ptr = presign_alloc(input.length);
      new Uint8Array(memory.buffer, ptr, input.length).set(input);
      const packed = presign_analyze(ptr, input.length);
      presign_free(ptr, input.length);
      const outPtr = Number(packed >> 32n);
      const outLen = Number(packed & 0xffffffffn);
      const out = dec.decode(new Uint8Array(memory.buffer, outPtr, outLen));
      presign_free(outPtr, outLen);
      return JSON.parse(out);
    },
  };
}
