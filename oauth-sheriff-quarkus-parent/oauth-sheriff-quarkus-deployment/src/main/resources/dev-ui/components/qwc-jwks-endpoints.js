import { html, css, LitElement } from 'lit';
import { devui } from 'devui';

export class QwcJwksEndpoints extends LitElement {
  static styles = css`
    .jwks-container {
      padding: 1rem;
    }

    .jwks-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }

    .jwks-title {
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

    .jwks-status {
      margin-bottom: 1rem;
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
    }

    .status-no-issuers {
      background-color: var(--lumo-error-color-10pct);
      border-color: var(--lumo-error-color-50pct);
      color: var(--lumo-error-text-color);
    }

    .status-configured {
      background-color: var(--lumo-success-color-10pct);
      border-color: var(--lumo-success-color-50pct);
      color: var(--lumo-success-text-color);
    }

    .issuers-grid {
      display: grid;
      gap: 1rem;
    }

    .issuer-card {
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      background-color: var(--lumo-base-color);
    }

    .issuer-name {
      margin-bottom: 0.5rem;
      color: var(--lumo-primary-text-color);
      font-size: 1.1rem;
      font-weight: 600;
    }

    .issuer-details {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 0.75rem;
    }

    .detail-item {
      padding: 0.5rem;
      border-radius: 4px;
      background-color: var(--lumo-contrast-5pct);
    }

    .detail-label {
      margin-bottom: 0.25rem;
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
    }

    .detail-value {
      color: var(--lumo-primary-text-color);
      font-family: monospace;
      font-size: 0.875rem;
      word-break: break-all;
    }

    .detail-value.not-configured {
      color: var(--lumo-error-text-color);
      font-style: italic;
    }

    .loader-status {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .status-indicator {
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }

    .status-unknown {
      background-color: var(--lumo-contrast-30pct);
    }

    .status-active {
      background-color: var(--lumo-success-color);
    }

    .status-error {
      background-color: var(--lumo-error-color);
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
  `;

  static properties = {
    _jwksStatus: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._jwksStatus = null;
    this._loading = true;
    this._error = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadJwksStatus();
  }

  async _loadJwksStatus() {
    try {
      this._loading = true;
      this._error = null;

      const response = await devui.jsonRPC.OAuthSheriffDevUI.getJwksStatus();
      this._jwksStatus = response;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error loading JWKS status:', error);
      this._error = `Failed to load JWKS status: ${error.message}`;
    } finally {
      this._loading = false;
    }
  }

  _refreshStatus() {
    this._loadJwksStatus();
  }

  _getStatusClass(status) {
    switch (status) {
      case 'NO_ISSUERS': {
        return 'status-no-issuers';
      }
      case 'CONFIGURED': {
        return 'status-configured';
      }
      default: {
        return '';
      }
    }
  }

  _getStatusMessage(status) {
    switch (status) {
      case 'NO_ISSUERS': {
        return 'No issuers are configured for JWT validation';
      }
      case 'CONFIGURED': {
        return 'JWKS endpoints are configured and available';
      }
      default: {
        return 'Unknown status';
      }
    }
  }

  render() {
    if (this._loading && !this._jwksStatus) {
      return html`<div class="loading" data-testid="jwks-loading">Loading JWKS endpoint status...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error" data-testid="jwks-error">
          ${this._error}
          <button class="refresh-button" @click="${this._refreshStatus}">Retry</button>
        </div>
      `;
    }

    if (!this._jwksStatus) {
      return html`<div class="loading">No JWKS status data available</div>`;
    }

    const status = this._jwksStatus;

    return html`
      <div class="jwks-container" data-testid="jwks-endpoints-container">
        <div class="jwks-header">
          <h3 class="jwks-title">JWKS Endpoints Status</h3>
          <button class="refresh-button" data-testid="jwks-refresh-button" @click="${this._refreshStatus}">
            Refresh
          </button>
        </div>

        <div class="jwks-status ${this._getStatusClass(status.status)}" data-testid="jwks-status-message">
          ${this._getStatusMessage(status.status)}
        </div>

        ${status.issuers && status.issuers.length > 0
          ? html`
              <div class="issuers-grid">
                ${status.issuers.map(
                  (issuer) => html`
                    <div class="issuer-card" data-testid="jwks-issuer-card">
                      <div class="issuer-name">${issuer.name}</div>

                      <div class="issuer-details">
                        <div class="detail-item">
                          <div class="detail-label">Issuer URI</div>
                          <div class="detail-value ${issuer.issuerUri === 'not configured' ? 'not-configured' : ''}">
                            ${issuer.issuerUri}
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">JWKS URI</div>
                          <div class="detail-value ${issuer.jwksUri === 'not configured' ? 'not-configured' : ''}">
                            ${issuer.jwksUri}
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">Loader Status</div>
                          <div class="loader-status">
                            <div class="status-indicator status-${issuer.loaderStatus.toLowerCase()}"></div>
                            <span class="detail-value">${issuer.loaderStatus}</span>
                          </div>
                        </div>

                        <div class="detail-item">
                          <div class="detail-label">Last Refresh</div>
                          <div class="detail-value">${issuer.lastRefresh}</div>
                        </div>
                      </div>
                    </div>
                  `
                )}
              </div>
            `
          : html` <div class="loading">No issuer configurations found</div> `}
      </div>
    `;
  }
}

customElements.define('qwc-jwks-endpoints', QwcJwksEndpoints);
