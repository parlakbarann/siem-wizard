/**
 * i18n - Internationalization Module
 * SIEM Wizard Multi-language Support
 * Supports: TR, EN, DE, HI, ES
 */

const i18n = {
    currentLang: 'en',
    translations: {},
    supportedLanguages: ['tr', 'en', 'de', 'hi', 'es'],
    languageNames: {
        tr: 'Türkçe',
        en: 'English',
        de: 'Deutsch',
        hi: 'हिन्दी',
        es: 'Español'
    },
    languageFlags: {
        tr: '🇹🇷',
        en: '🇬🇧',
        de: '🇩🇪',
        hi: '🇮🇳',
        es: '🇪🇸'
    },

    /**
     * Initialize i18n - loads saved language or default
     */
    async init() {
        const saved = localStorage.getItem('language') || 'en';
        await this.setLanguage(saved);
        this.renderLanguageSelector();
        return this;
    },

    /**
     * Set and load a new language
     */
    async setLanguage(lang) {
        if (!this.supportedLanguages.includes(lang)) {
            console.warn(`Language ${lang} not supported, falling back to 'en'`);
            lang = 'en';
        }

        try {
            const response = await fetch(`/i18n/${lang}.json`);
            if (!response.ok) throw new Error(`Failed to load ${lang}.json`);

            this.translations = await response.json();
            this.currentLang = lang;
            localStorage.setItem('language', lang);
            document.documentElement.lang = lang;

            this.updateDOM();
            this.updateLanguageSelector();

            // Dispatch event for dynamic components
            window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));

        } catch (error) {
            console.error('i18n load error:', error);
            if (lang !== 'tr') {
                // Fallback to Turkish
                await this.setLanguage('tr');
            }
        }
    },

    /**
     * Get translation by key (supports nested keys like "nav.home")
     */
    t(key, params = {}) {
        let text = key.split('.').reduce((obj, k) => obj?.[k], this.translations);

        if (text === undefined) {
            console.warn(`Translation missing: ${key}`);
            return key;
        }

        // Replace {param} placeholders
        Object.entries(params).forEach(([k, v]) => {
            text = text.replace(new RegExp(`\\{${k}\\}`, 'g'), v);
        });

        return text;
    },

    /**
     * Update all DOM elements with data-i18n attributes
     */
    updateDOM() {
        // Update text content
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.dataset.i18n;
            el.textContent = this.t(key);
        });

        // Update placeholders
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.dataset.i18nPlaceholder;
            el.placeholder = this.t(key);
        });

        // Update titles
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.dataset.i18nTitle;
            el.title = this.t(key);
        });

        // Update aria-labels
        document.querySelectorAll('[data-i18n-aria]').forEach(el => {
            const key = el.dataset.i18nAria;
            el.setAttribute('aria-label', this.t(key));
        });

        // Update page title if specified
        const titleEl = document.querySelector('[data-i18n-page-title]');
        if (titleEl) {
            document.title = this.t(titleEl.dataset.i18nPageTitle) + ' - SIEM Wizard';
        }
    },

    /**
     * Render language selector dropdown in navbar
     */
    renderLanguageSelector() {
        const container = document.getElementById('langSelector');
        if (!container) return;

        container.innerHTML = `
            <button class="lang-button" onclick="i18n.toggleLangDropdown()" title="${this.t('common.changeLanguage') || 'Change Language'}">
                <span class="lang-flag">${this.languageFlags[this.currentLang]}</span>
                <span class="lang-code">${this.currentLang.toUpperCase()}</span>
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
            </button>
            <div class="lang-dropdown" id="langDropdown">
                ${this.supportedLanguages.map(lang => `
                    <button class="lang-option ${lang === this.currentLang ? 'active' : ''}"
                            onclick="i18n.setLanguage('${lang}')">
                        <span class="lang-flag">${this.languageFlags[lang]}</span>
                        <span class="lang-name">${this.languageNames[lang]}</span>
                    </button>
                `).join('')}
            </div>
        `;
    },

    /**
     * Update language selector to show current language
     */
    updateLanguageSelector() {
        const flagEl = document.querySelector('.lang-button .lang-flag');
        const codeEl = document.querySelector('.lang-button .lang-code');

        if (flagEl) flagEl.textContent = this.languageFlags[this.currentLang];
        if (codeEl) codeEl.textContent = this.currentLang.toUpperCase();

        // Update active state in dropdown
        document.querySelectorAll('.lang-option').forEach(btn => {
            const lang = btn.onclick.toString().match(/'(\w+)'/)?.[1];
            btn.classList.toggle('active', lang === this.currentLang);
        });
    },

    /**
     * Toggle language dropdown visibility
     */
    toggleLangDropdown() {
        const dropdown = document.getElementById('langDropdown');
        if (dropdown) {
            dropdown.classList.toggle('show');
        }
    },

    /**
     * Close dropdown when clicking outside
     */
    setupClickOutside() {
        document.addEventListener('click', (e) => {
            const langSelector = document.getElementById('langSelector');
            const dropdown = document.getElementById('langDropdown');

            if (langSelector && dropdown && !langSelector.contains(e.target)) {
                dropdown.classList.remove('show');
            }
        });
    }
};

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        i18n.init();
        i18n.setupClickOutside();
    });
} else {
    i18n.init();
    i18n.setupClickOutside();
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = i18n;
}
