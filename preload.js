/**
 * Preload Script — Secure IPC Bridge
 * Exposes only whitelisted channels to renderer process
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const ALLOWED_SEND = [
  'scan:start', 'scan:stop', 'scan:pause',
  'export:json', 'export:html', 'export:pdf',
  'scan:get-history', 'scan:get-results',
];

const ALLOWED_ON = [
  'scan:progress', 'scan:found-page', 'scan:found-key',
  'scan:found-asset', 'scan:complete', 'scan:error',
  'scan:status', 'validate:result',
];

contextBridge.exposeInMainWorld('sentinel', {
  // Send message to main process
  send: (channel, data) => {
    if (ALLOWED_SEND.includes(channel)) {
      ipcRenderer.send(channel, data);
    } else {
      console.warn(`[Preload] Blocked channel: ${channel}`);
    }
  },

  // Invoke and await response from main process
  invoke: (channel, data) => {
    if (ALLOWED_SEND.includes(channel)) {
      return ipcRenderer.invoke(channel, data);
    }
    return Promise.reject(new Error(`Blocked channel: ${channel}`));
  },

  // Listen to events from main process
  on: (channel, callback) => {
    if (ALLOWED_ON.includes(channel)) {
      const sub = (_, ...args) => callback(...args);
      ipcRenderer.on(channel, sub);
      // Return cleanup function
      return () => ipcRenderer.removeListener(channel, sub);
    }
    console.warn(`[Preload] Blocked listener: ${channel}`);
    return () => {};
  },

  // Remove all listeners for a channel
  removeAllListeners: (channel) => {
    if (ALLOWED_ON.includes(channel)) {
      ipcRenderer.removeAllListeners(channel);
    }
  },
});
