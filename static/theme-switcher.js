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
  
  bindEvents() {
    // Theme dropdown selection
    const themeDropdown = document.getElementById('theme-dropdown');
    if (themeDropdown) {
      // Set the current theme as selected
      const options = themeDropdown.querySelectorAll('option');
      options.forEach(option => {
        if (option.value === this.currentTheme) {
          option.selected = true;
        }
      });
      
      // Add change event listener
      themeDropdown.addEventListener('change', () => {
        const themeId = themeDropdown.value;
        this.applyTheme(themeId);
        
        // Hide the dropdown after selection
        const themeDropdownContainer = document.getElementById('theme-dropdown-container');
        if (themeDropdownContainer) {
          themeDropdownContainer.classList.remove('active');
        }
      });
    }
    
    // Add event listener for the sidebar theme button
    const sidebarThemeButton = document.getElementById('sidebar-theme-button');
    const themeDropdownContainer = document.getElementById('theme-dropdown-container');
    
    if (sidebarThemeButton && themeDropdownContainer) {
      // Ensure dropdown is properly positioned relative to the button
      const updateDropdownPosition = () => {
        const sidebarItem = document.getElementById('sidebar-theme-item');
        const isCollapsed = document.querySelector('.app-container').classList.contains('sidebar-collapsed');
        
        if (isCollapsed) {
          // When sidebar is collapsed, position to the right of the sidebar
          themeDropdownContainer.style.left = 'var(--sidebar-collapsed-width)';
          themeDropdownContainer.style.top = `${sidebarItem.offsetTop}px`;
        } else {
          // When sidebar is expanded, position below the button
          themeDropdownContainer.style.left = '0';
          themeDropdownContainer.style.top = '100%';
        }
      };
      
      sidebarThemeButton.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation(); // Prevent event bubbling
        
        // Update position before showing
        updateDropdownPosition();
        
        // Toggle active class
        themeDropdownContainer.classList.toggle('active');
      });
      
      // Close dropdown when clicking outside
      document.addEventListener('click', (e) => {
        if (!sidebarThemeButton.contains(e.target) && 
            !themeDropdownContainer.contains(e.target)) {
          themeDropdownContainer.classList.remove('active');
        }
      });
      
      // Update position when sidebar is toggled
      const sidebarToggle = document.getElementById('sidebar-toggle');
      if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
          // Hide dropdown when sidebar state changes
          themeDropdownContainer.classList.remove('active');
          
          // Update position after a short delay to allow sidebar animation to complete
          setTimeout(() => {
            updateDropdownPosition();
          }, 300);
        });
      }
    }
  }
}

// Initialize the theme switcher
const themeSwitcher = new ThemeSwitcher();