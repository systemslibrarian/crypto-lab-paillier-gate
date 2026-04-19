/// <reference lib="WebWorker" />

import { generateKeyPair, type PaillierKeyPair } from './paillier';

type GenerateRequest = {
  type: 'generate';
  bitLength: number;
};

type ProgressMessage = {
  type: 'progress';
  stage: string;
  percent: number;
};

type SuccessMessage = {
  type: 'success';
  keyPair: PaillierKeyPair;
};

type ErrorMessage = {
  type: 'error';
  message: string;
};

type WorkerMessage = ProgressMessage | SuccessMessage | ErrorMessage;

declare const self: DedicatedWorkerGlobalScope;

self.onmessage = async (event: MessageEvent<GenerateRequest>) => {
  if (event.data.type !== 'generate') {
    return;
  }

  try {
    const keyPair = await generateKeyPair(event.data.bitLength, (stage, percent) => {
      const message: ProgressMessage = { type: 'progress', stage, percent };
      self.postMessage(message satisfies WorkerMessage);
    });

    const message: SuccessMessage = { type: 'success', keyPair };
    self.postMessage(message satisfies WorkerMessage);
  } catch (error) {
    const message: ErrorMessage = {
      type: 'error',
      message: error instanceof Error ? error.message : 'Key generation failed.',
    };
    self.postMessage(message satisfies WorkerMessage);
  }
};

export {};