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
    
    // Add hover event listeners for the sidebar theme item
    const sidebarThemeItem = document.getElementById('sidebar-theme-item');
    const themeDropdownContainer = document.getElementById('theme-dropdown-container');
    
    if (sidebarThemeItem && themeDropdownContainer) {
      // Ensure dropdown is properly positioned relative to the button
      const updateDropdownPosition = () => {
        const isCollapsed = document.querySelector('.app-container').classList.contains('sidebar-collapsed');
        
        if (isCollapsed) {
          // When sidebar is collapsed, position to the right of the sidebar
          themeDropdownContainer.style.left = 'var(--sidebar-collapsed-width)';
          themeDropdownContainer.style.top = 'auto';
          themeDropdownContainer.style.bottom = `calc(100% - ${sidebarThemeItem.offsetTop}px)`;
        } else {
          // When sidebar is expanded, position above the button
          themeDropdownContainer.style.left = '0';
          themeDropdownContainer.style.top = 'auto';
          themeDropdownContainer.style.bottom = '100%';
        }
      };
      
      // Show dropdown on mouseenter
      sidebarThemeItem.addEventListener('mouseenter', () => {
        // Update position before showing
        updateDropdownPosition();
        
        // Show dropdown
        themeDropdownContainer.classList.add('active');
      });
      
      // Hide dropdown when mouse leaves both the item and the dropdown
      sidebarThemeItem.addEventListener('mouseleave', (e) => {
        // Check if mouse is moving to the dropdown
        const toElement = e.relatedTarget;
        if (!themeDropdownContainer.contains(toElement)) {
          themeDropdownContainer.classList.remove('active');
        }
      });
      
      // Keep dropdown open when mouse is over it
      themeDropdownContainer.addEventListener('mouseenter', () => {
        themeDropdownContainer.classList.add('active');
      });
      
      // Hide dropdown when mouse leaves it
      themeDropdownContainer.addEventListener('mouseleave', () => {
        themeDropdownContainer.classList.remove('active');
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