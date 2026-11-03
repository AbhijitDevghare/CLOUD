let RedisLib = null;
try {
  RedisLib = require('ioredis');
} catch {
  RedisLib = null;
}

/**
 * In-memory Redis-compatible fallback store for local execution when a Redis daemon is not running.
 * Supports GET, SET with EX, DEL, INCR, EXPIRE, SADD, SMEMBERS, SREM, SISMEMBER, and sliding-window counters.
 */
class InMemoryRedisFallback {
  constructor() {
    this.store = new Map();
    this.sets = new Map();
    this.expirations = new Map();
    this.mode = 'IN_MEMORY_FALLBACK';
  }

  _checkExpired(key) {
    const exp = this.expirations.get(key);
    if (exp && Date.now() > exp) {
      this.store.delete(key);
      this.sets.delete(key);
      this.expirations.delete(key);
      return true;
    }
    return false;
  }

  async get(key) {
    this._checkExpired(key);
    return this.store.has(key) ? this.store.get(key) : null;
  }

  async set(key, value, mode, durationSec) {
    this.store.set(key, String(value));
    if (mode && String(mode).toUpperCase() === 'EX' && durationSec) {
      this.expirations.set(key, Date.now() + Number(durationSec) * 1000);
    }
    return 'OK';
  }

  async del(key) {
    this.store.delete(key);
    this.sets.delete(key);
    this.expirations.delete(key);
    return 1;
  }

  async incr(key) {
    this._checkExpired(key);
    const current = Number(this.store.get(key) || 0) + 1;
    this.store.set(key, String(current));
    return current;
  }

  async expire(key, seconds) {
    this.expirations.set(key, Date.now() + Number(seconds) * 1000);
    return 1;
  }

  async sadd(key, member) {
    this._checkExpired(key);
    if (!this.sets.has(key)) this.sets.set(key, new Set());
    this.sets.get(key).add(String(member));
    return 1;
  }

  async srem(key, member) {
    this._checkExpired(key);
    if (!this.sets.has(key)) return 0;
    this.sets.get(key).delete(String(member));
    return 1;
  }

  async smembers(key) {
    this._checkExpired(key);
    if (!this.sets.has(key)) return [];
    return Array.from(this.sets.get(key));
  }

  async sismember(key, member) {
    this._checkExpired(key);
    if (!this.sets.has(key)) return 0;
    return this.sets.get(key).has(String(member)) ? 1 : 0;
  }
}

let redisClient = null;
let redisMode = 'INITIALIZING';

async function initRedis() {
  if (redisClient) return redisClient;

  if (process.env.FORCE_IN_MEMORY_REDIS === 'true' || !RedisLib) {
    redisClient = new InMemoryRedisFallback();
    redisMode = 'IN_MEMORY_REDIS';
    return redisClient;
  }

  try {
    const candidate = new RedisLib(process.env.REDIS_URL || 'redis://localhost:6379', {
      connectTimeout: 1500,
      maxRetriesPerRequest: 1,
      retryStrategy: () => null
    });

    await new Promise((resolve, reject) => {
      candidate.once('ready', resolve);
      candidate.once('error', reject);
    });

    redisClient = candidate;
    redisMode = 'REDIS_SERVER';
    return redisClient;
  } catch {
    redisClient = new InMemoryRedisFallback();
    redisMode = 'IN_MEMORY_REDIS';
    return redisClient;
  }
}

function getRedisMode() {
  return redisMode;
}

module.exports = {
  initRedis,
  getRedisMode
};
