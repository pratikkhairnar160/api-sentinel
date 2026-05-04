/**
 * APISentinel - Main Electron Process
 * Authorized security assessment tool for detecting exposed API keys
 */

'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { setupIpcHandlers } = require('./src/ipc/handlers');
const { initDatabase } = require('./src/storage');
const logger = require('./src/utils/logger');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    title: 'APISentinel — API Key Security Scanner',
    backgroundColor: '#0d1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'gui/index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Open DevTools only in dev mode
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }
}

app.whenReady().then(async () => {
  try {
    await initDatabase();
    logger.info('Database initialized');
    createWindow();
    setupIpcHandlers(ipcMain, mainWindow);
    logger.info('APISentinel started');
  } catch (err) {
    logger.error('Startup failed:', err);
    dialog.showErrorBox('Startup Error', err.message);
    app.quit();
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
