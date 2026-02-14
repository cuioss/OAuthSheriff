import js from '@eslint/js';
import jsdoc from 'eslint-plugin-jsdoc';
import jest from 'eslint-plugin-jest';
import security from 'eslint-plugin-security';
import unicorn from 'eslint-plugin-unicorn';
import promise from 'eslint-plugin-promise';
import prettier from 'eslint-plugin-prettier';
import lit from 'eslint-plugin-lit';
import wc from 'eslint-plugin-wc';

export default [
  js.configs.recommended,
  {
    plugins: {
      jsdoc,
      jest,
      security,
      unicorn,
      promise,
      prettier,
      lit,
      wc,
    },
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        global: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
        document: 'readonly',
        window: 'readonly',
        HTMLElement: 'readonly',
        customElements: 'readonly',
        CSSStyleSheet: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        Headers: 'readonly',
        fetch: 'readonly',
        waitForComponentUpdate: 'readonly',
        navigator: 'readonly',
      },
    },
    rules: {
      // Core ESLint rules
      'no-console': 'warn',
      'no-debugger': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'prefer-const': 'error',
      'no-var': 'error',
      
      // Code quality rules (manual implementation of key SonarJS patterns)
      'complexity': ['warn', { max: 15 }],
      'max-statements': ['warn', { max: 20 }],
      'max-params': ['warn', { max: 5 }],
      
      // JSDoc rules
      'jsdoc/check-alignment': 'warn',
      'jsdoc/check-param-names': 'warn',
      'jsdoc/check-tag-names': 'warn',
      'jsdoc/require-description': 'off',
      'jsdoc/require-param': 'off',
      'jsdoc/require-param-description': 'off',
      'jsdoc/require-returns': 'off',
      'jsdoc/require-returns-description': 'off',
      
      // Security rules
      'security/detect-object-injection': 'warn',
      'security/detect-non-literal-regexp': 'warn',
      'security/detect-unsafe-regex': 'error',
      
      // Promise rules
      'promise/always-return': 'warn',
      'promise/catch-or-return': 'error',
      'promise/no-nesting': 'warn',
      'promise/no-return-wrap': 'error',
      
      // Unicorn rules for modern JavaScript
      'unicorn/prefer-module': 'error',
      'unicorn/prefer-node-protocol': 'error',
      'unicorn/no-array-for-each': 'off', // Allow forEach for readability
      'unicorn/prevent-abbreviations': 'off', // Allow common abbreviations
      
      // Lit-specific rules
      'lit/no-invalid-html': 'error',
      'lit/no-legacy-template-syntax': 'error',
      'lit/no-property-change-update': 'error',
      
      // Web Components rules
      'wc/no-constructor-attributes': 'error',
      'wc/no-invalid-element-name': 'error',
      
      // Prettier integration
      'prettier/prettier': 'error',
    },
  },
  {
    files: ['**/*.test.js', '**/test/**/*.js'],
    plugins: {
      jest,
    },
    languageOptions: {
      globals: {
        jest: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
      },
    },
    rules: {
      'jest/no-disabled-tests': 'warn',
      'jest/no-focused-tests': 'error',
      'jest/no-identical-title': 'error',
      'jest/prefer-to-have-length': 'warn',
      'jest/valid-expect': 'error',
    },
  },
];