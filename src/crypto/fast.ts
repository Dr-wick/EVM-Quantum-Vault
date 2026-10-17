// SPDX-License-Identifier: MIT
// Adapted from Aegis Protocol contributors (2026); see UPSTREAM-LICENSE.txt.
import { createKeccak, type IHasher } from 'hash-wasm';
import { makeCchs, type Cchs, type HashFn } from './cchs';

function bind(h: IHasher): HashFn {
  return data => {
    h.init(); h.update(data);
    return h.digest('binary').slice();
  };
}

let engine: Promise<Cchs> | undefined;
/** A single synchronous hash engine per worker. Do not share mutable WASM state across workers. */
export function fastCchs(): Promise<Cchs> {
  if (!engine) engine = createKeccak(256).then(h => makeCchs(bind(h))).catch(error => { engine = undefined; throw error; });
  return engine;
}
