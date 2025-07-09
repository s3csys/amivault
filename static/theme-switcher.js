/**
 * AMI Vault Theme Switcher
 * Handles theme switching, persistence, and UI interactions
 */

class ThemeSwitcher {
  constructor() {
    this.currentTheme = localStorage.getItem('ami-vault-theme') || 'datta-able-light';
    this.themeList = [
      // Light Themes
      { id: 'classic-light', name: 'Classic Light', category: 'light' },
      { id: 'soft-gray', name: 'Soft Gray', category: 'light' },
      { id: 'material-light', name: 'Material Light', category: 'light' },
      { id: 'flat-ui-light', name: 'Flat UI Light', category: 'light' },
      { id: 'minimal-white', name: 'Minimal White', category: 'light' },
      
      // Dark Themes
      { id: 'classic-dark', name: 'Classic Dark', category: 'dark' },
      { id: 'midnight-blue', name: 'Midnight Blue', category: 'dark' },
      { id: 'neon-dark', name: 'Neon Dark', category: 'dark' },
      { id: 'cyberpunk', name: 'Cyberpunk', category: 'dark' },
      { id: 'dark-gray', name: 'Dark Gray', category: 'dark' },
      
      // Hybrid Themes
      { id: 'tailwind-ui-light', name: 'Tailwind UI Light', category: 'hybrid' },
      { id: 'tailwind-ui-dark', name: 'Tailwind UI Dark', category: 'hybrid' },
      { id: 'ant-design-light', name: 'Ant Design Light', category: 'hybrid' },
      { id: 'ant-design-dark', name: 'Ant Design Dark', category: 'hybrid' },
      { id: 'bootstrap-light', name: 'Bootstrap Light', category: 'hybrid' },
      { id: 'bootstrap-dark', name: 'Bootstrap Dark', category: 'hybrid' },
      { id: 'datta-able-light', name: 'Datta Able Light', category: 'hybrid' },
      { id: 'datta-able-dark', name: 'Datta Able Dark', category: 'hybrid' },
      
      // Designer Themes
      { id: 'solarized-light', name: 'Solarized Light', category: 'designer' },
      { id: 'solarized-dark', name: 'Solarized Dark', category: 'designer' },
      { id: 'dracula', name: 'Dracula', category: 'designer' },
      { id: 'nord', name: 'Nord', category: 'designer' }
    ];
    
    this.init();
  }
  
  init() {
    // Apply the saved theme on page load
    this.applyTheme(this.currentTheme);
    
    // Initialize the theme switcher UI once DOM is loaded
    document.addEventListener('DOMContentLoaded', () => {
      this.createThemeSwitcherUI();
      this.bindEvents();
    });
  }
  
  applyTheme(themeId) {
    // Remove any existing theme classes
    document.body.classList.forEach(className => {
      if (className.startsWith('theme-')) {
        document.body.classList.remove(className);
      }
    });
    
    // Add the new theme class
    document.body.classList.add(`theme-${themeId}`);
    
    // Store the theme preference
    localStorage.setItem('ami-vault-theme', themeId);
    this.currentTheme = themeId;
    
    // Update UI if it exists
    const activeThemeElement = document.querySelector('.theme-switcher-active');
    if (activeThemeElement) {
      activeThemeElement.textContent = this.themeList.find(theme => theme.id === themeId).name;
    }
  }
  
  createThemeSwitcherUI() {
    // Create the theme switcher dropdown
    const themeDropdown = document.createElement('div');
    themeDropdown.className = 'theme-switcher-dropdown';
    themeDropdown.innerHTML = `
      <button class="theme-switcher-btn" aria-label="Switch theme">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"></circle>
          <path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"></path>
        </svg>
        <span class="theme-switcher-active">${this.themeList.find(theme => theme.id === this.currentTheme).name}</span>
      </button>
      <div class="theme-switcher-menu">
        <div class="theme-switcher-categories">
          <div class="theme-category-group">
            <h3>☀️ Light Themes</h3>
            ${this.generateThemeOptions('light')}
          </div>
          <div class="theme-category-group">
            <h3>🌙 Dark Themes</h3>
            ${this.generateThemeOptions('dark')}
          </div>
          <div class="theme-category-group">
            <h3>🌗 Hybrid Themes</h3>
            ${this.generateThemeOptions('hybrid')}
          </div>
          <div class="theme-category-group">
            <h3>🖼 Designer Themes</h3>
            ${this.generateThemeOptions('designer')}
          </div>
        </div>
      </div>
    `;
    
    // Add the theme switcher to the header
    const headerElement = document.querySelector('header');
    if (headerElement) {
      headerElement.appendChild(themeDropdown);
    }
  }
  
  generateThemeOptions(category) {
    return this.themeList
      .filter(theme => theme.category === category)
      .map(theme => `
        <button class="theme-option ${theme.id === this.currentTheme ? 'active' : ''}" 
                data-theme-id="${theme.id}" 
                aria-selected="${theme.id === this.currentTheme}">
          ${theme.name}
        </button>
      `).join('');
  }
  
  bindEvents() {
    // Toggle theme dropdown
    const themeBtn = document.querySelector('.theme-switcher-btn');
    const themeMenu = document.querySelector('.theme-switcher-menu');
    
    if (themeBtn && themeMenu) {
      themeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        themeMenu.classList.toggle('active');
      });
      
      // Close when clicking outside
      document.addEventListener('click', () => {
        themeMenu.classList.remove('active');
      });
      
      themeMenu.addEventListener('click', (e) => {
        e.stopPropagation();
      });
      
      // Theme selection
      document.querySelectorAll('.theme-option').forEach(option => {
        option.addEventListener('click', () => {
          const themeId = option.getAttribute('data-theme-id');
          this.applyTheme(themeId);
          
          // Update active state in UI
          document.querySelectorAll('.theme-option').forEach(opt => {
            opt.classList.remove('active');
            opt.setAttribute('aria-selected', 'false');
          });
          option.classList.add('active');
          option.setAttribute('aria-selected', 'true');
          
          // Close the menu
          themeMenu.classList.remove('active');
        });
      });
    }
  }
}

// Initialize the theme switcher
const themeSwitcher = new ThemeSwitcher();