/**
 * ipc/handlers.js
 * Electron IPC handler registration
 * Bridges GUI renderer ↔ main process scan pipeline
 */

'use strict';

const { shell, dialog } = require('electron');
const path              = require('path');
const os                = require('os');
const { ScanOrchestrator } = require('../scanOrchestrator');
const { generateReports, DEFAULT_OUTPUT_DIR } = require('../reporter');
const storage           = require('../storage');
const logger            = require('../utils/logger');

// Active scans map: scanId → orchestrator instance
const activeScans = new Map();

/**
 * Register all IPC handlers
 * @param {Electron.IpcMain} ipcMain
 * @param {Electron.BrowserWindow} mainWindow
 */
function setupIpcHandlers(ipcMain, mainWindow) {

  // Helper: safely send events to renderer
  const send = (channel, data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, data);
    }
  };

  // ── Start Scan ────────────────────────────────────────────────────────────
  ipcMain.handle('scan:start', async (_, config) => {
    try {
      // Validate required fields
      if (!config?.targetUrl) throw new Error('Target URL is required');
      const url = new URL(config.targetUrl); // throws if invalid
      if (!['http:', 'https:'].includes(url.protocol)) {
        throw new Error('Only HTTP/HTTPS targets are supported');
      }

      logger.info(`[IPC] scan:start → ${config.targetUrl}`);

      const orchestrator = new ScanOrchestrator(config);

      // Wire all orchestrator events → renderer
      orchestrator.on('status',         d => send('scan:status',      d));
      orchestrator.on('found-page',     d => send('scan:found-page',  d));
      orchestrator.on('found-asset',    d => send('scan:found-asset', d));
      orchestrator.on('found-key',      d => send('scan:found-key',   d));
      orchestrator.on('validate-result',d => send('validate:result',  d));
      orchestrator.on('complete',       d => send('scan:complete',    d));
      orchestrator.on('error',          d => send('scan:error',       d));
      orchestrator.on('stopped',        d => send('scan:status', { ...d, phase: 'stopped' }));

      activeScans.set(orchestrator.scanId, orchestrator);

      // Run scan in background (non-blocking)
      orchestrator.run().catch(err => {
        logger.error(`[IPC] Scan error: ${err.message}`);
        send('scan:error', { message: err.message });
      }).finally(() => {
        activeScans.delete(orchestrator.scanId);
      });

      return { scanId: orchestrator.scanId, status: 'started' };

    } catch (err) {
      logger.error(`[IPC] scan:start error: ${err.message}`);
      throw err;
    }
  });

  // ── Stop Scan ─────────────────────────────────────────────────────────────
  ipcMain.handle('scan:stop', async (_, { scanId }) => {
    const orch = activeScans.get(scanId);
    if (orch) {
      orch.stop();
      activeScans.delete(scanId);
      return { stopped: true };
    }
    return { stopped: false, reason: 'Scan not found or already finished' };
  });

  // ── Get Scan History ──────────────────────────────────────────────────────
  ipcMain.handle('scan:get-history', async () => {
    try {
      return storage.getScans();
    } catch (err) {
      logger.error(`[IPC] get-history error: ${err.message}`);
      return [];
    }
  });

  // ── Get Results for a Scan ─────────────────────────────────────────────────
  ipcMain.handle('scan:get-results', async (_, { scanId }) => {
    try {
      const scan     = storage.getScanById(scanId);
      const findings = storage.getFindingsForScan(scanId);
      const pages    = storage.getPagesForScan(scanId);
      return { scan, findings, pages };
    } catch (err) {
      logger.error(`[IPC] get-results error: ${err.message}`);
      throw err;
    }
  });

  // ── Export Reports ─────────────────────────────────────────────────────────
  ipcMain.handle('export:json', async (_, { scanId }) => _export(scanId, ['json'], send));
  ipcMain.handle('export:html', async (_, { scanId }) => _export(scanId, ['html'], send));
  ipcMain.handle('export:pdf',  async (_, { scanId }) => _export(scanId, ['pdf'],  send));
}

async function _export(scanId, formats, send) {
  try {
    const outputPaths = await generateReports(scanId, formats, DEFAULT_OUTPUT_DIR);
    const filePath    = Object.values(outputPaths)[0];

    if (filePath) {
      shell.showItemInFolder(filePath);
    }
    return { success: true, paths: outputPaths };
  } catch (err) {
    logger.error(`[IPC] Export failed: ${err.message}`);
    return { success: false, error: err.message };
  }
}

module.exports = { setupIpcHandlers };
