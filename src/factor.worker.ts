/// <reference lib="WebWorker" />

import { factorSemiprime, type FactorResult } from './factor';

type FactorRequest = {
  type: 'factor';
  N: bigint;
  budget: number;
};

type ProgressMessage = {
  type: 'progress';
  iterations: number;
};

type DoneMessage = {
  type: 'done';
  result: FactorResult;
};

type ErrorMessage = {
  type: 'error';
  message: string;
};

export type FactorWorkerMessage = ProgressMessage | DoneMessage | ErrorMessage;

declare const self: DedicatedWorkerGlobalScope;

self.onmessage = (event: MessageEvent<FactorRequest>) => {
  if (event.data.type !== 'factor') {
    return;
  }

  try {
    const result = factorSemiprime(event.data.N, event.data.budget, (iterations) => {
      self.postMessage({ type: 'progress', iterations } satisfies FactorWorkerMessage);
    });

    self.postMessage({ type: 'done', result } satisfies FactorWorkerMessage);
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: error instanceof Error ? error.message : 'Factoring failed.',
    } satisfies FactorWorkerMessage);
  }
};

export {};
