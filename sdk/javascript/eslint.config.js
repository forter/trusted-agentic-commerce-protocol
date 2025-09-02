import js from '@eslint/js';
import prettier from 'eslint-config-prettier';

export default [
  js.configs.recommended,
  prettier, // Must come last to override other configs
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        global: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        exports: 'writable',
        module: 'writable',
        require: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        DOMException: 'readonly',
        setImmediate: 'readonly',
        fetch: 'readonly'
      }
    },
    rules: {
      // Code quality rules (keep these)
      'no-console': 'warn',
      'no-unused-vars': 'error',
      'no-undef': 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      eqeqeq: 'error',
      curly: 'error',
      camelcase: 'error'
      // Formatting rules removed - handled by Prettier
    }
  }
];
