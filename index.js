import express from 'express';
import httpProxy from 'http-proxy';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// __dirname workaround for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const proxy = httpProxy.createProxyServer({});
const port = 3000;

// Load users.json for permissions
let users = JSON.parse(await fs.readFile(path.join(__dirname, 'users.json'), 'utf8'));

// Mapping of Docker API paths to permission flags
const permissionMap = [
  { pattern: /^\/v\d+\.\d+\/containers\/[^/]+\/(stop|restart|kill)$/, flag: 'ALLOW_RESTARTS' },
  { pattern: /^\/v\d+\.\d+\/containers\/[^/]+\/start$/, flag: 'ALLOW_START' },
  { pattern: /^\/v\d+\.\d+\/containers\/[^/]+\/stop$/, flag: 'ALLOW_STOP' },

  { pattern: /^\/v\d+\.\d+\/auth$/, flag: 'AUTH' },
  { pattern: /^\/v\d+\.\d+\/build.*$/, flag: 'BUILD' },
  { pattern: /^\/v\d+\.\d+\/commit.*$/, flag: 'COMMIT' },
  { pattern: /^\/v\d+\.\d+\/configs.*$/, flag: 'CONFIGS' },
  { pattern: /^\/v\d+\.\d+\/containers.*$/, flag: 'CONTAINERS' },
  { pattern: /^\/v\d+\.\d+\/distribution.*$/, flag: 'DISTRIBUTION' },
  { pattern: /^\/v\d+\.\d+\/events.*$/, flag: 'EVENTS' },
  { pattern: /^\/v\d+\.\d+\/exec.*$/, flag: 'EXEC' },
  { pattern: /^\/v\d+\.\d+\/grpc.*$/, flag: 'GRPC' },
  { pattern: /^\/v\d+\.\d+\/images.*$/, flag: 'IMAGES' },
  { pattern: /^\/v\d+\.\d+\/info$/, flag: 'INFO' },
  { pattern: /^\/v\d+\.\d+\/networks.*$/, flag: 'NETWORKS' },
  { pattern: /^\/v\d+\.\d+\/nodes.*$/, flag: 'NODES' },
  { pattern: /^\/v\d+\.\d+\/_ping$/, flag: 'PING' },
  { pattern: /^\/v\d+\.\d+\/plugins.*$/, flag: 'PLUGINS' },
  { pattern: /^\/v\d+\.\d+\/secrets.*$/, flag: 'SECRETS' },
  { pattern: /^\/v\d+\.\d+\/services.*$/, flag: 'SERVICES' },
  { pattern: /^\/v\d+\.\d+\/session.*$/, flag: 'SESSION' },
  { pattern: /^\/v\d+\.\d+\/swarm.*$/, flag: 'SWARM' },
  { pattern: /^\/v\d+\.\d+\/system.*$/, flag: 'SYSTEM' },
  { pattern: /^\/v\d+\.\d+\/tasks.*$/, flag: 'TASKS' },
  { pattern: /^\/v\d+\.\d+\/version$/, flag: 'VERSION' },
  { pattern: /^\/v\d+\.\d+\/volumes.*$/, flag: 'VOLUMES' },
  { pattern: /^\/v\d+\.\d+\/containers\/[^/]+\/logs$/, flag: 'LOGS' },


  // fallback wildcard
  { pattern: /^\/v\d+\.\d+\/.*$/, flag: 'ALL' }
];


// Match request path to a permission flag
function getRequiredPermissions(pathname) {
  return permissionMap
    .filter(entry => entry.pattern.test(pathname))
    .map(entry => entry.flag);
}

// Basic auth middleware
// app.use(async (req, res, next) => {
//   const auth = req.headers.authorization || '';
//   const token = auth.split(' ')[1];
//   if (!token) return res.status(401).send('Missing auth');

//   const [username, password] = Buffer.from(token, 'base64').toString().split(':');
//   const user = users[username];

//   if (!user || user.password !== password) {
//     return res.status(403).send('Invalid credentials');
//   }

//   req.user = user;
//   next();
// });
// Basic auth middleware
app.use(async (req, res, next) => {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) return res.status(401).send('Missing or invalid auth header');

  const token = auth.split(' ')[1];
  if (!token) return res.status(401).send('Missing auth token');

  let credentials;
  try {
    credentials = Buffer.from(token, 'base64').toString();
  } catch {
    return res.status(400).send('Invalid base64 auth encoding');
  }

  const [username, password] = credentials.split(':');
  if (!username || !password) return res.status(401).send('Malformed credentials');

  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(403).send('Invalid credentials');
  }

  req.user = user;
  next();
});


// Permission check + proxy to Docker socket
app.use((req, res) => {
  const user = req.user;
  const requiredPermissions = getRequiredPermissions(req.url);

  const hasPermission = requiredPermissions.every(flag => user.permissions?.[flag]);
  if (!hasPermission) {
    return res.status(403).send('Permission denied');
  }

  proxy.web(req, res, {
    socketPath: '/var/run/docker.sock',
    target: {
      socketPath: '/var/run/docker.sock',
    },
  }, (err) => {
    console.error('Proxy error:', err);
    res.status(500).send('Docker proxy error');
  });
});

app.listen(port, () => {
  console.log(`Proxy listening on http://localhost:${port}`);
});
// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down gracefully...');
  proxy.close();
  process.exit(0);
});
// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  proxy.close();
  process.exit(1);
});
// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection at:', promise, 'reason:', reason);
  proxy.close();
  process.exit(1);
});
// Handle SIGTERM for Docker container shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  proxy.close();
  process.exit(0);
});
// Handle SIGUSR2 for Docker container restart
process.on('SIGUSR2', () => {
  console.log('Received SIGUSR2, restarting gracefully...');
  proxy.close();
  process.exit(0);
});


