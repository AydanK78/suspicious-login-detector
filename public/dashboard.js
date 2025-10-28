// Dashboard JavaScript
class SuspiciousLoginDashboard {
    constructor() {
        this.apiBase = window.location.origin;
        this.socket = null;
        this.charts = {};
        this.isLiveFeedActive = false;
        this.feedItems = [];
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        await this.loadDashboardData();
        this.startPeriodicRefresh();
        this.updateLastUpdateTime();
    }

    setupEventListeners() {
        // Live feed controls
        document.getElementById('toggleFeed').addEventListener('click', () => {
            this.toggleLiveFeed();
        });

        document.getElementById('clearFeed').addEventListener('click', () => {
            this.clearFeed();
        });

        // Test login form
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.testLogin();
        });

        // Modal controls
        window.closeModal = () => {
            document.getElementById('loginModal').style.display = 'none';
        };

        // Global functions
        window.refreshDashboard = () => this.loadDashboardData();
        window.exportData = () => this.exportData();
        window.openSettings = () => this.openSettings();
    }

    async loadDashboardData() {
        try {
            // Load stats
            const statsResponse = await fetch(`${this.apiBase}/api/stats`);
            const stats = await statsResponse.json();
            this.updateStats(stats);

            // Load recent risk assessments
            const assessmentsResponse = await fetch(`${this.apiBase}/api/risk-assessments?limit=10`);
            const assessmentsData = await assessmentsResponse.json();
            this.updateRecentActivity(assessmentsData.assessments);

            // Update charts
            this.updateCharts(stats);

            this.updateLastUpdateTime();
            this.updateSystemHealth(true);

        } catch (error) {
            console.error('Error loading dashboard data:', error);
            this.updateSystemHealth(false);
        }
    }

    updateStats(stats) {
        document.getElementById('totalUsers').textContent = stats.uniqueUsers || 0;
        document.getElementById('totalLogins').textContent = stats.totalLogins || 0;
        document.getElementById('suspiciousLogins').textContent = stats.suspiciousLogins || 0;
        
        const riskRate = stats.totalLogins > 0 
            ? ((stats.suspiciousLogins / stats.totalLogins) * 100).toFixed(1)
            : 0;
        document.getElementById('riskRate').textContent = `${riskRate}%`;
    }

    updateRecentActivity(assessments) {
        const container = document.getElementById('recentActivity');
        
        if (!assessments || assessments.length === 0) {
            container.innerHTML = '<div class="loading">No recent high-risk activities</div>';
            return;
        }

        const html = assessments.map(assessment => {
            const timeAgo = this.getTimeAgo(new Date(assessment.timestamp));
            const riskClass = assessment.riskLevel.toLowerCase();
            
            return `
                <div class="activity-item ${riskClass}">
                    <div class="activity-icon">${this.getRiskIcon(assessment.riskLevel)}</div>
                    <div class="activity-content">
                        <div class="activity-user">User: ${assessment.userId}</div>
                        <div class="activity-details">Risk Score: ${assessment.overallRisk}/100</div>
                        <div class="activity-time">${timeAgo}</div>
                    </div>
                    <div class="activity-risk ${riskClass}">${assessment.riskLevel.toUpperCase()}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = html;
    }

    updateCharts(stats) {
        this.updateRiskChart(stats.riskBreakdown || {});
        this.updateActivityChart();
    }

    updateRiskChart(riskBreakdown) {
        const ctx = document.getElementById('riskChart').getContext('2d');
        
        if (this.charts.risk) {
            this.charts.risk.destroy();
        }

        const labels = Object.keys(riskBreakdown);
        const data = Object.values(riskBreakdown);
        const colors = {
            low: '#28a745',
            medium: '#ffc107',
            high: '#fd7e14',
            critical: '#dc3545'
        };

        this.charts.risk = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels.map(label => label.charAt(0).toUpperCase() + label.slice(1)),
                datasets: [{
                    data: data,
                    backgroundColor: labels.map(label => colors[label] || '#6c757d'),
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    }

    updateActivityChart() {
        const ctx = document.getElementById('activityChart').getContext('2d');
        
        if (this.charts.activity) {
            this.charts.activity.destroy();
        }

        // Generate sample data for the last 24 hours
        const hours = [];
        const loginData = [];
        const suspiciousData = [];
        
        for (let i = 23; i >= 0; i--) {
            const hour = new Date();
            hour.setHours(hour.getHours() - i);
            hours.push(hour.getHours() + ':00');
            
            // Simulate login activity (in real app, this would come from API)
            loginData.push(Math.floor(Math.random() * 50) + 10);
            suspiciousData.push(Math.floor(Math.random() * 5) + 1);
        }

        this.charts.activity = new Chart(ctx, {
            type: 'line',
            data: {
                labels: hours,
                datasets: [{
                    label: 'Total Logins',
                    data: loginData,
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Suspicious Logins',
                    data: suspiciousData,
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    }

    toggleLiveFeed() {
        const button = document.getElementById('toggleFeed');
        
        if (this.isLiveFeedActive) {
            this.stopLiveFeed();
            button.textContent = 'Start Live Feed';
            button.classList.remove('btn-secondary');
            button.classList.add('btn-primary');
        } else {
            this.startLiveFeed();
            button.textContent = 'Stop Live Feed';
            button.classList.remove('btn-primary');
            button.classList.add('btn-secondary');
        }
    }

    startLiveFeed() {
        this.isLiveFeedActive = true;
        this.connectWebSocket();
        
        // Simulate live login events for demo
        this.simulateLiveLogins();
    }

    stopLiveFeed() {
        this.isLiveFeedActive = false;
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
        this.updateWebSocketStatus(false);
    }

    connectWebSocket() {
        // Load Socket.IO from CDN
        if (typeof io === 'undefined') {
            const script = document.createElement('script');
            script.src = 'https://cdn.socket.io/4.7.2/socket.io.min.js';
            script.onload = () => this.initializeSocket();
            document.head.appendChild(script);
        } else {
            this.initializeSocket();
        }
    }

    initializeSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Socket.IO connected');
            this.updateWebSocketStatus(true);
        });
        
        this.socket.on('login_analyzed', (data) => {
            this.handleLiveLogin(data);
        });
        
        this.socket.on('disconnect', () => {
            console.log('Socket.IO disconnected');
            this.updateWebSocketStatus(false);
        });
        
        this.socket.on('connect_error', (error) => {
            console.error('Socket.IO error:', error);
            this.updateWebSocketStatus(false);
        });
    }

    simulateLiveLogins() {
        if (!this.isLiveFeedActive) return;

        const users = ['alice', 'bob', 'charlie', 'david', 'eve'];
        const ips = ['8.8.8.8', '1.1.1.1', '133.130.96.1', '106.51.0.1', '81.2.69.142'];
        
        const simulateLogin = () => {
            if (!this.isLiveFeedActive) return;

            const login = {
                userId: users[Math.floor(Math.random() * users.length)],
                ipAddress: ips[Math.floor(Math.random() * ips.length)],
                success: Math.random() > 0.1,
                timestamp: new Date().toISOString(),
                riskLevel: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
                overallRisk: Math.floor(Math.random() * 100)
            };

            this.handleLiveLogin(login);
            
            // Schedule next login
            setTimeout(simulateLogin, Math.random() * 5000 + 2000);
        };

        simulateLogin();
    }

    handleLiveLogin(login) {
        this.addToFeed(login);
        
        // If it's a high-risk login, also add to recent activity
        if (login.riskLevel === 'high' || login.riskLevel === 'critical') {
            this.addToRecentActivity(login);
        }
    }

    addToFeed(login) {
        const feedContainer = document.getElementById('loginFeed');
        const feedItem = document.createElement('div');
        
        const riskClass = login.riskLevel.toLowerCase();
        const timeStr = new Date(login.timestamp).toLocaleTimeString();
        
        feedItem.className = `feed-item ${riskClass}`;
        feedItem.innerHTML = `
            <div class="activity-icon">${this.getRiskIcon(login.riskLevel)}</div>
            <div class="activity-content">
                <div class="activity-user">${login.userId}</div>
                <div class="activity-details">${login.ipAddress} • ${login.success ? 'Success' : 'Failed'}</div>
                <div class="activity-time">${timeStr}</div>
            </div>
            <div class="activity-risk ${riskClass}">${login.overallRisk}</div>
        `;

        feedContainer.insertBefore(feedItem, feedContainer.firstChild);
        
        // Keep only last 20 items
        while (feedContainer.children.length > 20) {
            feedContainer.removeChild(feedContainer.lastChild);
        }

        // Add animation
        feedItem.style.animation = 'slideIn 0.3s ease';
    }

    addToRecentActivity(login) {
        const container = document.getElementById('recentActivity');
        const activityItem = document.createElement('div');
        
        const riskClass = login.riskLevel.toLowerCase();
        const timeAgo = this.getTimeAgo(new Date(login.timestamp));
        
        activityItem.className = `activity-item ${riskClass}`;
        activityItem.innerHTML = `
            <div class="activity-icon">${this.getRiskIcon(login.riskLevel)}</div>
            <div class="activity-content">
                <div class="activity-user">User: ${login.userId}</div>
                <div class="activity-details">Risk Score: ${login.overallRisk}/100</div>
                <div class="activity-time">${timeAgo}</div>
            </div>
            <div class="activity-risk ${riskClass}">${login.riskLevel.toUpperCase()}</div>
        `;

        container.insertBefore(activityItem, container.firstChild);
        
        // Keep only last 10 items
        while (container.children.length > 10) {
            container.removeChild(container.lastChild);
        }
    }

    clearFeed() {
        document.getElementById('loginFeed').innerHTML = '<div class="feed-placeholder">Feed cleared</div>';
    }

    async testLogin() {
        const userId = document.getElementById('testUserId').value;
        const ipAddress = document.getElementById('testIpAddress').value;
        const success = document.getElementById('testSuccess').value === 'true';

        try {
            const response = await fetch(`${this.apiBase}/api/login/check`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    userId,
                    ipAddress,
                    success,
                    timestamp: new Date().toISOString()
                })
            });

            const result = await response.json();
            
            // Show result in a simple alert (in real app, use a proper modal)
            alert(`Login Analysis Result:\nRisk Level: ${result.riskLevel}\nRisk Score: ${result.overallRisk}/100\nRecommendations: ${result.recommendations.join(', ')}`);
            
            // Refresh dashboard to show updated data
            this.loadDashboardData();
            
            // Close modal
            document.getElementById('loginModal').style.display = 'none';
            
        } catch (error) {
            console.error('Error testing login:', error);
            alert('Error testing login. Please try again.');
        }
    }

    updateSystemHealth(isHealthy) {
        const statusIndicator = document.getElementById('statusIndicator');
        const apiStatus = document.getElementById('apiStatus');
        
        if (isHealthy) {
            statusIndicator.textContent = '🟢 Online';
            apiStatus.textContent = '🟢 Online';
        } else {
            statusIndicator.textContent = '🔴 Offline';
            apiStatus.textContent = '🔴 Offline';
        }
    }

    updateWebSocketStatus(connected) {
        const wsStatus = document.getElementById('wsStatus');
        wsStatus.textContent = connected ? '🟢 Connected' : '🔴 Disconnected';
    }

    updateLastUpdateTime() {
        const now = new Date();
        document.getElementById('lastUpdate').textContent = now.toLocaleTimeString();
    }

    startPeriodicRefresh() {
        // Refresh dashboard every 30 seconds
        setInterval(() => {
            if (!this.isLiveFeedActive) {
                this.loadDashboardData();
            }
        }, 30000);
    }

    getRiskIcon(riskLevel) {
        const icons = {
            low: '✅',
            medium: '⚠️',
            high: '🚨',
            critical: '🔥'
        };
        return icons[riskLevel.toLowerCase()] || '❓';
    }

    getTimeAgo(date) {
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        if (diffInSeconds < 60) return 'Just now';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
        return `${Math.floor(diffInSeconds / 86400)}d ago`;
    }

    exportData() {
        // In a real app, this would generate and download a report
        alert('Export functionality would generate a comprehensive security report here.');
    }

    openSettings() {
        // In a real app, this would open a settings modal
        alert('Settings panel would allow configuration of risk thresholds and alerts here.');
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    new SuspiciousLoginDashboard();
});

// Add some demo functionality
window.openTestModal = () => {
    document.getElementById('loginModal').style.display = 'block';
};
