// Format dates using browser's locale
function formatDate(timestamp) {
    if (!timestamp) return "N/A";
    
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Format file size to human-readable format
function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

// When the document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Add loading spinner to form submissions
    const scanForms = document.querySelectorAll('.scan-form');
    scanForms.forEach(form => {
        form.addEventListener('submit', function() {
            this.classList.add('is-submitting');
        });
    });
    
    // Style reputation scores based on value
    const reputationScores = document.querySelectorAll('.reputation-score');
    reputationScores.forEach(score => {
        const value = parseInt(score.textContent);
        if (value >= 80) {
            score.classList.add('reputation-score-high');
        } else if (value >= 50) {
            score.classList.add('reputation-score-medium');
        } else {
            score.classList.add('reputation-score-low');
        }
    });
});