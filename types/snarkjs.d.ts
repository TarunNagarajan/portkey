// Minimal types for the parts of snarkjs this project uses; the package ships
// no type declarations.
declare module 'snarkjs' {
  export interface Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }

  export const groth16: {
    fullProve(
      input: Record<string, string | number>,
      wasmFile: string | Uint8Array,
      zkeyFile: string | Uint8Array,
    ): Promise<{ proof: Proof; publicSignals: string[] }>;
    prove(
      zkeyFile: string | Uint8Array,
      witnessFile: string | Uint8Array,
    ): Promise<{ proof: Proof; publicSignals: string[] }>;
    verify(verificationKey: unknown, publicSignals: string[], proof: Proof): Promise<boolean>;
  };

  export const wtns: {
    calculate(
      input: Record<string, string | number>,
      wasmFile: string,
      wtnsFile: string,
      options?: { singleThread?: boolean },
    ): Promise<void>;
  };
}
