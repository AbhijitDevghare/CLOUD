let JoiLib = null;
try {
  JoiLib = require('joi');
} catch {
  JoiLib = null;
}

class FieldValidator {
  constructor(type) {
    this.type = type;
    this.isRequired = false;
    this.minLen = null;
    this.maxLen = null;
    this.validValues = null;
    this.defaultValue = undefined;
    this.isEmail = false;
  }

  email() {
    this.isEmail = true;
    return this;
  }

  min(n) {
    this.minLen = n;
    return this;
  }

  max(n) {
    this.maxLen = n;
    return this;
  }

  valid(...vals) {
    this.validValues = vals;
    return this;
  }

  default(val) {
    this.defaultValue = val;
    return this;
  }

  items() {
    return this;
  }

  required() {
    this.isRequired = true;
    return this;
  }
}

class ObjectValidator {
  constructor(schemaMap) {
    this.schemaMap = schemaMap;
  }

  validate(input = {}) {
    const value = { ...(input || {}) };
    for (const [key, rule] of Object.entries(this.schemaMap)) {
      let val = value[key];
      if ((val === undefined || val === null) && rule.defaultValue !== undefined) {
        val = typeof rule.defaultValue === 'function' ? rule.defaultValue() : rule.defaultValue;
        value[key] = val;
      }

      if (rule.isRequired && (val === undefined || val === null || val === '')) {
        return {
          error: { details: [{ message: `"${key}" is required` }] },
          value
        };
      }

      if (val !== undefined && val !== null) {
        if (rule.type === 'string') {
          if (typeof val !== 'string') {
            return { error: { details: [{ message: `"${key}" must be a string` }] }, value };
          }
          if (rule.isEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
            return { error: { details: [{ message: `"${key}" must be a valid email` }] }, value };
          }
          if (rule.minLen !== null && val.length < rule.minLen) {
            return {
              error: { details: [{ message: `"${key}" length must be at least ${rule.minLen} characters` }] },
              value
            };
          }
          if (rule.maxLen !== null && val.length > rule.maxLen) {
            return {
              error: { details: [{ message: `"${key}" length must be at most ${rule.maxLen} characters` }] },
              value
            };
          }
        }
        if (rule.validValues && !rule.validValues.includes(val)) {
          return {
            error: {
              details: [{ message: `"${key}" must be one of [${rule.validValues.join(', ')}]` }]
            },
            value
          };
        }
      }
    }
    return { error: null, value };
  }
}

const NativeJoi = {
  object: (map) => ( map ? new ObjectValidator(map) : new FieldValidator('object') ),
  string: () => new FieldValidator('string'),
  array: () => new FieldValidator('array'),
  number: () => new FieldValidator('number'),
  boolean: () => new FieldValidator('boolean')
};

module.exports = JoiLib || NativeJoi;
