// Dashboard JavaScript for Realtime IDS

document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const statusText = document.getElementById('status-text');
    const uptimeText = document.getElementById('uptime-text');
    // Bỏ nút start/stop: không còn tham chiếu
    const startButton = null;
    const stopButton = null;
    const packetsProcessed = document.getElementById('packets-processed');
    const packetsPerSecond = document.getElementById('packets-per-second');
    const bytesProcessed = document.getElementById('bytes-processed');
    const flowsAnalyzed = document.getElementById('flows-analyzed');
    const alertsGenerated = document.getElementById('alerts-generated');
    const alertsTable = document.getElementById('alerts-table');
    
    // System metrics elements
    const cpuUsage = document.getElementById('cpu-usage');
    const cpuBar = document.getElementById('cpu-bar');
    const memUsage = document.getElementById('mem-usage');
    const memBar = document.getElementById('mem-bar');
    const connectionsCount = document.getElementById('connections-count');
    
    // Format numbers with commas
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    // Format bytes to human-readable format
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Format uptime to readable format
    function formatUptime(seconds) {
        if (!seconds) return '--';
        
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        let result = '';
        if (days > 0) result += days + 'd ';
        if (hours > 0) result += hours + 'h ';
        if (minutes > 0) result += minutes + 'm ';
        result += secs + 's';
        
        return result;
    }
    
    // Update system metrics (CPU, RAM, Network)
    function updateSystemMetrics() {
        fetch('/api/system-metrics')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('System metrics error:', data.error);
                    return;
                }
                
                // Update CPU
                const cpu = data.cpu.percent.toFixed(1);
                cpuUsage.textContent = cpu + '%';
                cpuBar.style.width = cpu + '%';
                cpuBar.textContent = cpu + '%';
                
                // CPU color based on load
                if (cpu > 80) {
                    cpuBar.className = 'progress-bar bg-danger';
                } else if (cpu > 50) {
                    cpuBar.className = 'progress-bar bg-warning';
                } else {
                    cpuBar.className = 'progress-bar bg-success';
                }
                
                // Update Memory
                const mem = data.memory.percent.toFixed(1);
                memUsage.textContent = mem + '%';
                memBar.style.width = mem + '%';
                memBar.textContent = mem + '%';
                
                // Memory color based on usage
                if (mem > 80) {
                    memBar.className = 'progress-bar bg-danger';
                } else if (mem > 50) {
                    memBar.className = 'progress-bar bg-warning';
                } else {
                    memBar.className = 'progress-bar bg-success';
                }
                
                // Update connections count
                const connTotal = data.connections.total;
                const connEst = data.connections.established;
                connectionsCount.textContent = `${formatNumber(connEst)} / ${formatNumber(connTotal)}`;
                
                // Highlight if too many connections (potential DOS)
                if (connEst > 500) {
                    connectionsCount.className = 'text-danger fw-bold';
                } else if (connEst > 100) {
                    connectionsCount.className = 'text-warning fw-bold';
                } else {
                    connectionsCount.className = 'text-primary';
                }
            })
            .catch(error => console.error('Error fetching system metrics:', error));
    }
    
    // Update stats every second
    function updateStats() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                // Update status
                if (data.start_time) {
                    statusText.textContent = 'Đang chạy';
                    statusText.className = 'text-success';
                    uptimeText.textContent = 'Thời gian chạy: ' + formatUptime(data.uptime);
                } else {
                    // Trường hợp không có start_time vẫn hiển thị đang chạy (hệ thống luôn bật)
                    statusText.textContent = 'Đang chạy';
                    statusText.className = 'text-success';
                    uptimeText.textContent = 'Thời gian chạy: --';
                }
                
                // Update statistics
                packetsProcessed.textContent = formatNumber(data.packets_processed);
                packetsPerSecond.textContent = formatNumber(data.packets_per_second);
                bytesProcessed.textContent = formatBytes(data.bytes_processed);
                flowsAnalyzed.textContent = formatNumber(data.flows_analyzed);
                alertsGenerated.textContent = formatNumber(data.alerts_generated);
            })
            .catch(error => {
                console.error('Error fetching stats:', error);
            });
    }
    
    // Update alerts table
    function updateAlerts() {
        fetch('/api/alerts')
            .then(response => response.json())
            .then(alerts => {
                if (alerts.length === 0) {
                    alertsTable.innerHTML = '<tr><td colspan="4" class="text-center">Chưa có cảnh báo</td></tr>';
                    return;
                }
                
                // Sort alerts by time (newest first)
                alerts.sort((a, b) => {
                    return new Date(b.timestamp) - new Date(a.timestamp);
                });
                
                // Limit to 10 most recent alerts
                const recentAlerts = alerts.slice(0, 10);
                
                // Clear table
                alertsTable.innerHTML = '';
                
                // Add alerts to table
                recentAlerts.forEach(alert => {
                    const row = document.createElement('tr');
                    
                    // Time column - format to HH:MM:SS
                    const timeCell = document.createElement('td');
                    const timestamp = new Date(alert.timestamp);
                    timeCell.textContent = timestamp.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    
                    // Type column with badge
                    const typeCell = document.createElement('td');
                    const typeBadge = document.createElement('span');

                    // Gom nhóm hiển thị trên UI: luôn hiển thị 'ATTACK'
                    const detailType = (alert.detail_type || alert.type || 'attack')
                        .toString()
                        .toLowerCase()
                        .replace(/\s+/g, '_');

                    // Luôn dùng style 'attack' cho badge trên UI
                    typeBadge.className = 'badge badge-attack';

                    // Văn bản hiển thị: ATTACK
                    typeBadge.textContent = 'ATTACK';

                    // Giữ chi tiết loại tấn công ở tooltip (native title)
                    if (detailType && detailType !== 'attack') {
                        const niceDetail = detailType.toUpperCase().replace(/_/g, ' ');
                        typeBadge.title = `Chi tiết: ${niceDetail}`;
                    }
                    typeCell.appendChild(typeBadge);
                    
                    // Source column
                    const sourceCell = document.createElement('td');
                    if (alert.src_ip) {
                        sourceCell.textContent = `${alert.src_ip}:${alert.src_port || '?'}`;
                    } else {
                        sourceCell.textContent = '?';
                    }
                    
                    // Destination column
                    const destCell = document.createElement('td');
                    if (alert.dst_ip) {
                        destCell.textContent = `${alert.dst_ip}:${alert.dst_port || '?'}`;
                    } else {
                        destCell.textContent = '?';
                    }
                    
                    // Add cells to row
                    row.appendChild(timeCell);
                    row.appendChild(typeCell);
                    row.appendChild(sourceCell);
                    row.appendChild(destCell);
                    
                    // Add row to table
                    alertsTable.appendChild(row);
                });
            })
            .catch(error => {
                console.error('Error fetching alerts:', error);
            });
    }
    
    // Handle start button click
    // Bỏ logic start/stop vì hệ thống luôn chạy
    
    // Initial update
    updateStats();
    updateAlerts();
    updateSystemMetrics();
    
    // Update stats every second
    setInterval(updateStats, 1000);
    
    // Update alerts every 5 seconds
    setInterval(updateAlerts, 5000);
    
    // Update system metrics every 2 seconds
    setInterval(updateSystemMetrics, 2000);
});