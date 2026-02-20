import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwtConfig extends LitElement {
  static styles = css`
    .config-container {
      max-width: 1200px;
      padding: 1rem;
    }

    .config-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }

    .config-title {
      margin: 0;
      font-size: 1.2rem;
      font-weight: 600;
    }

    .refresh-button {
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 4px;
      background-color: var(--lumo-primary-color);
      color: var(--lumo-primary-contrast-color);
      font-size: 0.875rem;
      cursor: pointer;
    }

    .refresh-button:hover {
      background-color: var(--lumo-primary-color-50pct);
    }

    .config-sections {
      display: grid;
      gap: 1.5rem;
    }

    .config-section {
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      background-color: var(--lumo-base-color);
    }

    .section-title {
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      color: var(--lumo-primary-text-color);
      font-size: 1.1rem;
      font-weight: 600;
      border-bottom: 1px solid var(--lumo-contrast-10pct);
    }

    .config-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1rem;
    }

    .config-item {
      padding: 0.75rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
    }

    .config-label {
      margin-bottom: 0.25rem;
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
      font-weight: 500;
    }

    .config-value {
      color: var(--lumo-primary-text-color);
      font-family: Monaco, Menlo, 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      word-break: break-all;
    }

    .config-value.boolean {
      font-weight: 600;
    }

    .config-value.true {
      color: var(--lumo-success-text-color);
    }

    .config-value.false {
      color: var(--lumo-error-text-color);
    }

    .config-value.null {
      color: var(--lumo-secondary-text-color);
      font-style: italic;
    }

    .issuers-section {
      margin-top: 1rem;
    }

    .issuer-card {
      margin-bottom: 1rem;
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
    }

    .issuer-name {
      margin-bottom: 0.75rem;
      color: var(--lumo-primary-color);
      font-size: 1rem;
      font-weight: 600;
    }

    .loading {
      padding: 2rem;
      color: var(--lumo-secondary-text-color);
      text-align: center;
    }

    .error {
      padding: 1rem;
      border: 1px solid var(--lumo-error-color-50pct);
      border-radius: 6px;
      background-color: var(--lumo-error-color-10pct);
      color: var(--lumo-error-text-color);
    }

    .no-issuers {
      padding: 2rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
      color: var(--lumo-secondary-text-color);
      text-align: center;
    }

    .health-indicator {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.25rem 0.75rem;
      border-radius: 4px;
      font-size: 0.875rem;
      font-weight: 500;
    }

    .health-healthy {
      border: 1px solid var(--lumo-success-color-50pct);
      background-color: var(--lumo-success-color-10pct);
      color: var(--lumo-success-text-color);
    }

    .health-issues {
      border: 1px solid var(--lumo-error-color-50pct);
      background-color: var(--lumo-error-color-10pct);
      color: var(--lumo-error-text-color);
    }

    .health-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .health-dot.healthy {
      background-color: var(--lumo-success-color);
    }

    .health-dot.issues {
      background-color: var(--lumo-error-color);
    }
  `;

  static properties = {
    _configuration: { state: true },
    _healthInfo: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._configuration = null;
    this._healthInfo = null;
    this._loading = true;
    this._error = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadConfiguration();
  }

  async _loadConfiguration() {
    try {
      this._loading = true;
      this._error = null;

      const [config, health] = await Promise.all([
        devui.jsonRPC.OAuthSheriffDevUI.getConfiguration(),
        devui.jsonRPC.OAuthSheriffDevUI.getHealthInfo(),
      ]);

      this._configuration = config;
      this._healthInfo = health;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error loading JWT configuration:', error);
      this._error = `Failed to load configuration: ${error.message}`;
    } finally {
      this._loading = false;
    }
  }

  _refreshConfiguration() {
    this._loadConfiguration();
  }

  _formatValue(value) {
    if (value === null || value === undefined) {
      return { text: 'not set', className: 'null' };
    }
    if (typeof value === 'boolean') {
      return { text: value.toString(), className: `boolean ${value}` };
    }
    if (typeof value === 'string' && value.length === 0) {
      return { text: 'empty', className: 'null' };
    }
    return { text: value.toString(), className: '' };
  }

  _renderGeneralConfiguration(config) {
    return html`
      <div class="config-section" data-testid="jwt-config-general-section">
        <h4 class="section-title">General Settings</h4>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Enabled</div>
            <div class="config-value ${this._formatValue(config.enabled).className}">
              ${this._formatValue(config.enabled).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Log Level</div>
            <div class="config-value">${config.logLevel}</div>
          </div>
        </div>
      </div>
    `;
  }

  _renderParserConfiguration(config) {
    return html`
      <div class="config-section" data-testid="jwt-config-parser-section">
        <h4 class="section-title">Parser Configuration</h4>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Max Token Size</div>
            <div class="config-value">${config.parser.maxTokenSize} bytes</div>
          </div>
          <div class="config-item">
            <div class="config-label">Clock Skew</div>
            <div class="config-value">${config.parser.clockSkewSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Expiration Time</div>
            <div class="config-value ${this._formatValue(config.parser.requireExpirationTime).className}">
              ${this._formatValue(config.parser.requireExpirationTime).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Not Before Time</div>
            <div class="config-value ${this._formatValue(config.parser.requireNotBeforeTime).className}">
              ${this._formatValue(config.parser.requireNotBeforeTime).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Issued At Time</div>
            <div class="config-value ${this._formatValue(config.parser.requireIssuedAtTime).className}">
              ${this._formatValue(config.parser.requireIssuedAtTime).text}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  _renderHttpConfiguration(config) {
    return html`
      <div class="config-section">
        <h4 class="section-title">HTTP JWKS Loader Configuration</h4>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Connect Timeout</div>
            <div class="config-value">${config.httpJwksLoader.connectTimeoutSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Read Timeout</div>
            <div class="config-value">${config.httpJwksLoader.readTimeoutSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Size Limit</div>
            <div class="config-value">${config.httpJwksLoader.sizeLimit} bytes</div>
          </div>
          <div class="config-item">
            <div class="config-label">Cache TTL</div>
            <div class="config-value">${config.httpJwksLoader.cacheTtlSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Cache Size</div>
            <div class="config-value">${config.httpJwksLoader.cacheSize}</div>
          </div>
          <div class="config-item">
            <div class="config-label">Background Refresh</div>
            <div class="config-value ${this._formatValue(config.httpJwksLoader.backgroundRefreshEnabled).className}">
              ${this._formatValue(config.httpJwksLoader.backgroundRefreshEnabled).text}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  _renderIssuersConfiguration(config) {
    return html`
      <div class="config-section" data-testid="jwt-config-issuers-section">
        <h4 class="section-title">Configured Issuers</h4>
        ${config.issuers && Object.keys(config.issuers).length > 0
          ? html`
              <div class="issuers-section">
                ${Object.entries(config.issuers).map(
                  ([name, issuerConfig]) => html`
                    <div class="issuer-card">
                      <div class="issuer-name">${name}</div>
                      <div class="config-grid">
                        <div class="config-item">
                          <div class="config-label">Issuer URI</div>
                          <div class="config-value ${this._formatValue(issuerConfig.issuerUri).className}">
                            ${this._formatValue(issuerConfig.issuerUri).text}
                          </div>
                        </div>
                        <div class="config-item">
                          <div class="config-label">JWKS URI</div>
                          <div class="config-value ${this._formatValue(issuerConfig.jwksUri).className}">
                            ${this._formatValue(issuerConfig.jwksUri).text}
                          </div>
                        </div>
                        <div class="config-item">
                          <div class="config-label">Audience</div>
                          <div class="config-value ${this._formatValue(issuerConfig.audience).className}">
                            ${this._formatValue(issuerConfig.audience).text}
                          </div>
                        </div>
                        <div class="config-item">
                          <div class="config-label">Public Key Location</div>
                          <div class="config-value ${this._formatValue(issuerConfig.publicKeyLocation).className}">
                            ${this._formatValue(issuerConfig.publicKeyLocation).text}
                          </div>
                        </div>
                        <div class="config-item">
                          <div class="config-label">Algorithm Preference</div>
                          <div class="config-value">
                            ${issuerConfig.algorithmPreference
                              ? issuerConfig.algorithmPreference.join(', ')
                              : 'default'}
                          </div>
                        </div>
                      </div>
                    </div>
                  `
                )}
              </div>
            `
          : html` <div class="no-issuers">No issuers configured. JWT validation will not be available.</div> `}
      </div>
    `;
  }

  render() {
    if (this._loading && !this._configuration) {
      return html`<div class="loading" data-testid="jwt-config-loading">Loading JWT configuration...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error" data-testid="jwt-config-error">
          ${this._error}
          <button class="refresh-button" @click="${this._refreshConfiguration}">Retry</button>
        </div>
      `;
    }

    if (!this._configuration) {
      return html`<div class="loading">No configuration data available</div>`;
    }

    const config = this._configuration;
    const health = this._healthInfo;

    return html`
      <div class="config-container" data-testid="jwt-config-container">
        <div class="config-header">
          <h3 class="config-title">JWT Configuration</h3>
          <div style="display: flex; align-items: center; gap: 1rem;">
            ${health
              ? html`
                  <div
                    class="health-indicator ${health.overallStatus === 'HEALTHY' ? 'health-healthy' : 'health-issues'}"
                    data-testid="jwt-config-health-indicator"
                  >
                    <div class="health-dot ${health.overallStatus === 'HEALTHY' ? 'healthy' : 'issues'}"></div>
                    ${health.overallStatus === 'HEALTHY' ? 'Healthy' : 'Issues Detected'}
                  </div>
                `
              : ''}
            <button
              class="refresh-button"
              data-testid="jwt-config-refresh-button"
              @click="${this._refreshConfiguration}"
            >
              Refresh
            </button>
          </div>
        </div>

        <div class="config-sections">
          ${this._renderGeneralConfiguration(config)} ${this._renderParserConfiguration(config)}
          ${this._renderHttpConfiguration(config)} ${this._renderIssuersConfiguration(config)}
          ${health && health.issues && health.issues.length > 0
            ? html`
                <div class="config-section">
                  <h4 class="section-title">Configuration Issues</h4>
                  <div style="color: var(--lumo-error-text-color);">
                    ${health.issues.map((issue) => html` <div style="margin-bottom: 0.5rem;">• ${issue}</div> `)}
                  </div>
                </div>
              `
            : ''}
        </div>
      </div>
    `;
  }
}

customElements.define('qwc-jwt-config', QwcJwtConfig);
