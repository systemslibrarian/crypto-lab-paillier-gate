/// <reference lib="WebWorker" />

import { factorSemiprime, type FactorResult } from './factor';

type FactorRequest = {
  type: 'factor';
  requestId: number;
  N: bigint;
  budget: number;
};

type ProgressMessage = {
  type: 'progress';
  requestId: number;
  iterations: number;
};

type DoneMessage = {
  type: 'done';
  requestId: number;
  result: FactorResult;
};

type ErrorMessage = {
  type: 'error';
  requestId: number;
  message: string;
};

export type FactorWorkerMessage = ProgressMessage | DoneMessage | ErrorMessage;

declare const self: DedicatedWorkerGlobalScope;

self.onmessage = (event: MessageEvent<FactorRequest>) => {
  if (event.data.type !== 'factor') {
    return;
  }

  try {
    const { requestId } = event.data;
    const result = factorSemiprime(event.data.N, event.data.budget, (iterations) => {
      self.postMessage({ type: 'progress', requestId, iterations } satisfies FactorWorkerMessage);
    });

    self.postMessage({ type: 'done', requestId, result } satisfies FactorWorkerMessage);
  } catch (error) {
    self.postMessage({
      type: 'error',
      requestId: event.data.requestId,
      message: error instanceof Error ? error.message : 'Factoring failed.',
    } satisfies FactorWorkerMessage);
  }
};

export {};
