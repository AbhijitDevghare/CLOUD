const { URL } = require('url');

let expressLib = null;
try {
  expressLib = require('express');
} catch {
  expressLib = null;
}

/**
 * Matches a route pattern like '/accounts/:id/scan' against an incoming pathname.
 */
function matchRoutePattern(pattern, pathname) {
  const normPattern = pattern.replace(/\/+$/, '') || '/';
  const normPath = pathname.replace(/\/+$/, '') || '/';

  const patParts = normPattern.split('/');
  const pathParts = normPath.split('/');
  if (patParts.length !== pathParts.length) return null;

  const params = {};
  for (let i = 0; i < patParts.length; i += 1) {
    const p = patParts[i];
    const actual = pathParts[i];
    if (p.startsWith(':')) {
      params[p.slice(1)] = decodeURIComponent(actual);
    } else if (p !== actual) {
      return null;
    }
  }
  return params;
}

function createNativeRouter() {
  const stack = [];

  const router = {
    _isRouter: true,
    _stack: stack,
    use(pathOrFn, maybeFn) {
      if (typeof pathOrFn === 'function') {
        stack.push({ type: 'middleware', prefix: '/', fn: pathOrFn });
      } else if (maybeFn && maybeFn._isRouter) {
        stack.push({ type: 'subrouter', prefix: pathOrFn.replace(/\/+$/, ''), router: maybeFn });
      } else if (typeof maybeFn === 'function') {
        stack.push({ type: 'middleware', prefix: pathOrFn.replace(/\/+$/, ''), fn: maybeFn });
      }
      return this;
    }
  };

  for (const method of ['get', 'post', 'patch', 'put', 'delete']) {
    router[method] = (routePath, ...handlers) => {
      stack.push({
        type: 'route',
        method: method.toUpperCase(),
        path: routePath,
        handlers
      });
      return router;
    };
  }

  return router;
}

function createNativeApp() {
  const settings = new Map();
  const rootRouter = createNativeRouter();

  async function dispatchStack(routerInstance, basePrefix, req, res) {
    for (const layer of routerInstance._stack) {
      if (res.writableEnded) return true;

      if (layer.type === 'middleware') {
        if (req.pathname.startsWith(layer.prefix === '/' ? '' : layer.prefix)) {
          let nextCalled = false;
          await new Promise((resolve, reject) => {
            const next = (err) => {
              if (err) return reject(err);
              nextCalled = true;
              resolve();
            };
            try {
              const maybePromise = layer.fn(req, res, next);
              if (maybePromise && typeof maybePromise.then === 'function') {
                maybePromise.then(() => {
                  if (res.writableEnded) resolve();
                }).catch(reject);
              } else if (res.writableEnded) {
                resolve();
              }
            } catch (e) {
              reject(e);
            }
          });
          if (!nextCalled && res.writableEnded) return true;
        }
      } else if (layer.type === 'subrouter') {
        const fullPrefix = `${basePrefix}${layer.prefix}`;
        if (req.pathname === fullPrefix || req.pathname.startsWith(`${fullPrefix}/`)) {
          req.baseUrl = fullPrefix;
          const handled = await dispatchStack(layer.router, fullPrefix, req, res);
          if (handled || res.writableEnded) return true;
        }
      } else if (layer.type === 'route') {
        if (req.method === layer.method) {
          const fullPattern = `${basePrefix}${layer.path === '/' ? '' : layer.path}` || '/';
          const params = matchRoutePattern(fullPattern, req.pathname);
          if (params) {
            req.params = params;
            for (const handler of layer.handlers) {
              if (res.writableEnded) return true;
              let nextCalled = false;
              await new Promise((resolve, reject) => {
                const next = (err) => {
                  if (err) return reject(err);
                  nextCalled = true;
                  resolve();
                };
                try {
                  const out = handler(req, res, next);
                  if (out && typeof out.then === 'function') {
                    out.then(() => {
                      if (res.writableEnded) resolve();
                    }).catch(reject);
                  } else if (res.writableEnded) {
                    resolve();
                  }
                } catch (e) {
                  reject(e);
                }
              });
              if (!nextCalled && res.writableEnded) return true;
            }
            return true;
          }
        }
      }
    }
    return false;
  }

  const app = async (req, res) => {
    const parsedUrl = new URL(req.url || '/', 'http://localhost');
    req.originalUrl = req.url || '/';
    req.pathname = parsedUrl.pathname;
    req.query = Object.fromEntries(parsedUrl.searchParams.entries());
    req.headers = req.headers || {};
    req.app = app;
    req.ip = req.socket?.remoteAddress || '127.0.0.1';

    res.statusCode = 200;
    res.status = (code) => {
      res.statusCode = code;
      return res;
    };
    res.json = (obj) => {
      if (!res.writableEnded) {
        const str = JSON.stringify(obj);
        if (typeof res.setHeader === 'function') {
          res.setHeader('Content-Type', 'application/json');
        }
        res.writableEnded = true;
        res._jsonData = obj;
        if (typeof res.end === 'function') {
          res.end(str);
        }
      }
      return res;
    };

    if (req.body === undefined && typeof req.on === 'function') {
      const raw = await new Promise((resolve) => {
        let buf = '';
        req.on('data', (c) => { buf += c; });
        req.on('end', () => resolve(buf));
      });
      try {
        req.body = raw ? JSON.parse(raw) : {};
      } catch {
        req.body = {};
      }
    }

    try {
      const handled = await dispatchStack(rootRouter, '', req, res);
      if (!handled && !res.writableEnded) {
        res.status(404).json({ error: 'NOT_FOUND', path: req.pathname });
      }
    } catch (err) {
      if (!res.writableEnded) {
        res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
      }
    }
  };

  app.set = (k, v) => settings.set(k, v);
  app.get = (kOrPath, ...handlers) => {
    if (handlers.length === 0) return settings.get(kOrPath);
    return rootRouter.get(kOrPath, ...handlers);
  };
  app.post = (...args) => rootRouter.post(...args);
  app.patch = (...args) => rootRouter.patch(...args);
  app.put = (...args) => rootRouter.put(...args);
  app.delete = (...args) => rootRouter.delete(...args);
  app.use = (...args) => rootRouter.use(...args);

  /**
   * In-process HTTP request injector for running integration tests without opening TCP sockets.
   */
  app.inject = async ({ method = 'GET', url = '/', headers = {}, body = null }) => {
    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }
    const req = {
      method: method.toUpperCase(),
      url,
      headers: normalizedHeaders,
      body: body || {},
      socket: { remoteAddress: normalizedHeaders['x-forwarded-for'] || '127.0.0.1' }
    };
    const res = {
      statusCode: 200,
      writableEnded: false,
      _jsonData: null,
      setHeader: () => {},
      end: () => {}
    };
    await app(req, res);
    return { status: res.statusCode, data: res._jsonData };
  };

  return app;
}

function getExpress() {
  if (expressLib) {
    return expressLib;
  }
  const fn = () => createNativeApp();
  fn.Router = () => createNativeRouter();
  fn.json = () => (req, res, next) => next();
  return fn;
}

module.exports = getExpress();
