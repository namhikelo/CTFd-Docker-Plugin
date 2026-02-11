CTFd.plugin.run((_CTFd) => {
    const $ = _CTFd.lib.$;
    const md = _CTFd.lib.markdown();
    
    // Disable flag modal popup for container challenges
    // Container challenges auto-generate flags based on flag_mode setting
    window.challenge = window.challenge || {};
    window.challenge.data = window.challenge.data || {};
    window.challenge.data.flags = [];
});

// Parse flag pattern and auto-fill hidden fields
function parseFlagPattern() {
    const pattern = document.getElementById('flag_pattern').value;
    const preview = document.getElementById('flag_pattern_preview');
    
    // Check for random pattern: <ran_N> where N is the length
    const randomMatch = pattern.match(/<ran_(\d+)>/);
    
    if (randomMatch) {
        // Random mode detected
        const randomLength = parseInt(randomMatch[1]);
        const parts = pattern.split(randomMatch[0]);
        
        document.getElementById('flag_mode').value = 'random';
        document.getElementById('flag_prefix').value = parts[0] || '';
        document.getElementById('flag_suffix').value = parts[1] || '';
        document.getElementById('random_flag_length').value = randomLength;
        
        // SECURITY: Build preview using DOM methods to prevent XSS
        const exampleRandom = 'x'.repeat(randomLength);
        preview.textContent = '';
        preview.appendChild(document.createTextNode('✓ Random mode: '));
        const codeEl = document.createElement('code');
        codeEl.textContent = (parts[0] || '') + exampleRandom + (parts[1] || '');
        preview.appendChild(codeEl);
        preview.appendChild(document.createTextNode(` (${randomLength} random chars)`));
        preview.style.color = '#17a2b8';
    } else {
        // Static mode
        document.getElementById('flag_mode').value = 'static';
        document.getElementById('flag_prefix').value = pattern;
        document.getElementById('flag_suffix').value = '';
        document.getElementById('random_flag_length').value = 0;
        
        // SECURITY: Build preview using DOM methods to prevent XSS
        preview.textContent = '';
        preview.appendChild(document.createTextNode('✓ Static mode: '));
        const codeEl = document.createElement('code');
        codeEl.textContent = pattern;
        preview.appendChild(codeEl);
        preview.appendChild(document.createTextNode(' (same for all teams)'));
        preview.style.color = '#28a745';
    }
}

// Add event listener for flag pattern input
document.addEventListener('DOMContentLoaded', function() {
    const flagPatternInput = document.getElementById('flag_pattern');
    if (flagPatternInput) {
        flagPatternInput.addEventListener('input', parseFlagPattern);
        // Parse initial value after it's been set
        setTimeout(parseFlagPattern, 100);
    }
});

// Toggle between standard and dynamic scoring
document.getElementById('scoring_type').addEventListener('change', function() {
    const scoringType = this.value;
    const standardSection = document.getElementById('standard-scoring');
    const dynamicSection = document.getElementById('dynamic-scoring');
    
    if (scoringType === 'standard') {
        standardSection.style.display = 'block';
        dynamicSection.style.display = 'none';
        
        // Set required on standard fields
        document.getElementById('standard_value').required = true;
        document.getElementById('dynamic_initial').required = false;
        document.getElementById('dynamic_decay').required = false;
        document.getElementById('dynamic_minimum').required = false;
        
        // Disable dynamic fields so they won't be submitted
        document.getElementById('dynamic_initial').disabled = true;
        document.getElementById('dynamic_decay').disabled = true;
        document.getElementById('dynamic_minimum').disabled = true;
        document.getElementById('decay_function').disabled = true;
        
        // Enable standard field
        document.getElementById('standard_value').disabled = false;
    } else {
        standardSection.style.display = 'none';
        dynamicSection.style.display = 'block';
        
        // Set required on dynamic fields
        document.getElementById('standard_value').required = false;
        document.getElementById('dynamic_initial').required = true;
        document.getElementById('dynamic_decay').required = true;
        document.getElementById('dynamic_minimum').required = true;
        
        // Disable standard field so it won't be submitted
        document.getElementById('standard_value').disabled = true;
        
        // Enable dynamic fields
        document.getElementById('dynamic_initial').disabled = false;
        document.getElementById('dynamic_decay').disabled = false;
        document.getElementById('dynamic_minimum').disabled = false;
        document.getElementById('decay_function').disabled = false;
    }
});

// Load Docker images
var containerImage = document.getElementById("container-image");
var containerImageDefault = document.getElementById("container-image-default");

fetch("/admin/containers/api/images", {
    method: "GET",
    headers: {
        "Accept": "application/json",
        "CSRF-Token": init.csrfNonce
    }
})
.then(response => response.json())
.then(data => {
    if (data.error) {
        // SECURITY: Use textContent to prevent XSS from server data
        containerImageDefault.textContent = data.error;
    } else {
        for (var i = 0; i < data.images.length; i++) {
            var opt = document.createElement("option");
            opt.value = data.images[i];
            opt.textContent = data.images[i];
            containerImage.appendChild(opt);
        }
        containerImageDefault.textContent = "Choose an image...";
        containerImage.removeAttribute("disabled");
        
        // Set selected image from challenge data
        if (typeof container_image_selected !== 'undefined') {
            containerImage.value = container_image_selected;
        }
    }
})
.catch(error => {
    console.error("Error loading images:", error);
    containerImageDefault.textContent = "Error loading images";
});

// Set connection type value from challenge data
var connectType = document.getElementById("connect-type");
if (connectType && typeof container_connection_type_selected !== 'undefined') {
    connectType.value = container_connection_type_selected;
}

// Toggle SSH credentials visibility based on connection type
var connectionTypeSelect = document.getElementById('connect-type');
var sshCredentialsDiv = document.getElementById('ssh-credentials');

if (connectionTypeSelect && sshCredentialsDiv) {
    function toggleSSHCredentials() {
        if (connectionTypeSelect.value === 'ssh') {
            sshCredentialsDiv.style.display = 'block';
        } else {
            sshCredentialsDiv.style.display = 'none';
        }
    }
    
    connectionTypeSelect.addEventListener('change', toggleSSHCredentials);
    toggleSSHCredentials(); // Initial call
}