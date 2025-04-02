/**
 * QR Phishing Detector - Frontend JavaScript
 * Handles UI interactions and API calls for QR code phishing detection
 */

document.addEventListener('DOMContentLoaded', function() {
    // API endpoint configuration
    const API_BASE_URL = '';  // Empty string to use relative URLs since we're serving from the same server
    
    // DOM Elements
    const dropArea = document.getElementById('drop-area');
    const fileInput = document.getElementById('file-input');
    const filenameDisplay = document.getElementById('filename-display');
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const analyzeUrlBtn = document.getElementById('analyze-url-btn');
    const checkContentToggle = document.getElementById('check-content');
    const loadingSection = document.getElementById('loading');
    const resultsSection = document.getElementById('results');
    const newScanBtn = document.getElementById('new-scan-btn');
    const detailsBtn = document.getElementById('details-btn');
    const visitBtn = document.getElementById('visit-btn');
    const detailedReport = document.getElementById('detailed-report');
    const closeReportBtn = document.getElementById('close-report-btn');
    
    // Result display elements
    const qrImage = document.getElementById('qr-image');
    const qrContent = document.getElementById('qr-content');
    const qrType = document.getElementById('qr-type');
    const riskScore = document.getElementById('risk-score');
    const riskStatus = document.getElementById('risk-status');
    const riskLevel = document.getElementById('risk-level');
    const riskPointer = document.getElementById('risk-pointer');
    const riskFactors = document.getElementById('risk-factors');
    const modelConfidence = document.getElementById('model-confidence');
    const recommendationsContent = document.getElementById('recommendations-content');
    const urlFeatures = document.getElementById('url-features');
    const ruleAnalysis = document.getElementById('rule-analysis');
    const modelPrediction = document.getElementById('model-prediction');
    const jsonDetails = document.getElementById('json-details');
    
    // Currently selected file
    let selectedFile = null;
    
    // Last analysis results
    let lastAnalysisResults = null;
    
    // Event Listeners for Drag & Drop
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });
    
    function highlight() {
        dropArea.classList.add('dragover');
    }
    
    function unhighlight() {
        dropArea.classList.remove('dragover');
    }
    
    // Handle file drop
    dropArea.addEventListener('drop', handleDrop, false);
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length) {
            handleFile(files[0]);
        }
    }
    
    // Handle file selection via input
    fileInput.addEventListener('change', function() {
        if (this.files.length) {
            handleFile(this.files[0]);
        }
    });
    
    // Process the selected file
    function handleFile(file) {
        // Check if the file is an image
        if (!file.type.match('image.*')) {
            alert('Please select an image file');
            return;
        }
        
        selectedFile = file;
        filenameDisplay.textContent = file.name;
        scanBtn.disabled = false;
        
        // Preview the image if desired (optional)
        const reader = new FileReader();
        reader.onload = function(e) {
            qrImage.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
    
    // Scan QR Code button click
    scanBtn.addEventListener('click', function() {
        if (!selectedFile) {
            alert('Please select a QR code image first');
            return;
        }
        
        performQRScan(selectedFile);
    });
    
    // Analyze URL button click
    analyzeUrlBtn.addEventListener('click', function() {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a URL to analyze');
            return;
        }
        
        performURLAnalysis(url);
    });
    
    // New scan button click
    newScanBtn.addEventListener('click', function() {
        resetUI();
    });
    
    // Show details button click
    detailsBtn.addEventListener('click', function() {
        detailedReport.style.display = 'block';
    });
    
    // Close report button click
    closeReportBtn.addEventListener('click', function() {
        detailedReport.style.display = 'none';
    });
    
    // Perform QR code scan and analysis
    function performQRScan(file) {
        // Show loading
        loadingSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        
        // Create form data
        const formData = new FormData();
        formData.append('image', file);
        formData.append('check_content', checkContentToggle.checked);
        
        // Call API
        fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || 'Error scanning QR code');
                });
            }
            return response.json();
        })
        .then(data => {
            // Store results
            lastAnalysisResults = data;
            
            // Display results
            displayResults(data);
        })
        .catch(error => {
            alert('Error: ' + error.message);
            loadingSection.classList.add('hidden');
        });
    }
    
    // Perform URL analysis
    function performURLAnalysis(url) {
        // Show loading
        loadingSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        
        // Prepare request body
        const requestData = {
            url: url,
            check_content: checkContentToggle.checked
        };
        
        // Call API
        fetch(`${API_BASE_URL}/analyze_url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || 'Error analyzing URL');
                });
            }
            return response.json();
        })
        .then(data => {
            // Create mock QR data for display
            const mockQRData = {
                status: 'success',
                qr_code: {
                    detected: true,
                    data: data.url,
                    is_url: true
                },
                phishing_analysis: data.phishing_analysis
            };
            
            // Store results
            lastAnalysisResults = mockQRData;
            
            // Display results
            displayResults(mockQRData);
        })
        .catch(error => {
            alert('Error: ' + error.message);
            loadingSection.classList.add('hidden');
        });
    }
    
    // Display analysis results
    function displayResults(data) {
        // Hide loading
        if (loadingSection) {
            loadingSection.classList.add('hidden');
        }
        
        // Populate QR content
        if (qrContent) {
            qrContent.textContent = data.qr_code.data;
        }
        
        if (qrType) {
            qrType.textContent = data.qr_code.is_url ? 'URL' : 'Text';
        }
        
        // If it's a URL from QR code, set the visualization
        if (data.visualization && qrImage) {
            qrImage.src = API_BASE_URL + data.visualization;
        }
        
        // If the QR code contains a URL, display phishing analysis
        if (data.qr_code.is_url && data.phishing_analysis) {
            displayPhishingAnalysis(data.phishing_analysis);
            
            // Set visit URL button
            if (visitBtn) {
                visitBtn.href = data.qr_code.data;
                visitBtn.classList.remove('hidden');
            }
        } else {
            // For non-URL QR codes
            if (riskScore) {
                riskScore.textContent = '0';
            }
            
            if (riskStatus) {
                riskStatus.textContent = 'Safe';
                riskStatus.style.backgroundColor = 'var(--success-color)';
            }
            
            // Reset risk gauge
            const riskLevelElement = document.getElementById('risk-level');
            const riskPointerElement = document.getElementById('risk-pointer');
            
            if (riskLevelElement) {
                riskLevelElement.style.transform = 'rotate(0deg)';
            }
            
            if (riskPointerElement) {
                riskPointerElement.style.transform = 'rotate(0deg)';
            }
            
            // Clear risk factors
            if (riskFactors) {
                riskFactors.innerHTML = '<li class="placeholder">No URL to analyze</li>';
            }
            
            // Show only safe recommendation
            if (recommendationsContent) {
                const children = recommendationsContent.children;
                if (children && children.length) {
                    Array.from(children).forEach(child => {
                        child.classList.add('hidden');
                    });
                    
                    const safeElement = recommendationsContent.querySelector('.safe');
                    if (safeElement) {
                        safeElement.classList.remove('hidden');
                        safeElement.textContent = 'This QR code contains text, not a URL.';
                    }
                }
            }
            
            // Hide visit button
            if (visitBtn) {
                visitBtn.classList.add('hidden');
            }
        }
        
        // Show results
        if (resultsSection) {
            resultsSection.classList.remove('hidden');
        }
    }
    
    // Display phishing analysis results
    function displayPhishingAnalysis(analysis) {
        const finalAssessment = analysis.final_assessment;
        const explanation = analysis.explanation || {};
        const isPhishing = finalAssessment.is_phishing;
        const riskLevel = finalAssessment.risk_level;
        const confidence = finalAssessment.confidence;
        
        // Calculate and display risk score
        let scoreValue = 0;
        if (analysis.model_based && analysis.model_based.probability) {
            scoreValue = Math.round(analysis.model_based.probability * 100);
        } else if (analysis.rule_based && analysis.rule_based.score) {
            scoreValue = Math.round(analysis.rule_based.score * 100);
        }
        
        if (riskScore) {
            riskScore.textContent = scoreValue;
        }
        
        // Set risk status text and color
        if (riskStatus) {
            riskStatus.textContent = riskLevel;
            
            if (riskLevel.includes('High')) {
                riskStatus.style.backgroundColor = 'var(--danger-color)';
                if (riskScore) riskScore.style.color = 'var(--danger-color)';
            } else if (riskLevel.includes('Medium')) {
                riskStatus.style.backgroundColor = 'var(--warning-color)';
                if (riskScore) riskScore.style.color = 'var(--warning-color)';
            } else {
                riskStatus.style.backgroundColor = 'var(--success-color)';
                if (riskScore) riskScore.style.color = 'var(--success-color)';
            }
        }
        
        // Set risk gauge - with null checks to prevent errors
        const gaugeRotation = Math.min(180, Math.max(0, scoreValue * 1.8));
        if (document.getElementById('risk-level')) {
            document.getElementById('risk-level').style.transform = `rotate(${gaugeRotation}deg)`;
        }
        if (document.getElementById('risk-pointer')) {
            document.getElementById('risk-pointer').style.transform = `rotate(${gaugeRotation}deg)`;
        }
        
        // Display risk factors
        if (riskFactors) {
            const factors = explanation.triggered_factors || [];
            if (factors.length > 0 && factors[0] !== 'No suspicious factors detected') {
                riskFactors.innerHTML = '';
                factors.forEach(factor => {
                    const li = document.createElement('li');
                    li.textContent = factor;
                    riskFactors.appendChild(li);
                });
            } else {
                riskFactors.innerHTML = '<li class="placeholder">No suspicious factors detected</li>';
            }
        }
        
        // Display model confidence
        if (modelConfidence) {
            modelConfidence.textContent = confidence ? confidence.charAt(0).toUpperCase() + confidence.slice(1) : 'N/A';
        }
        
        // Display recommendations
        if (recommendationsContent) {
            Array.from(recommendationsContent.children).forEach(child => {
                child.classList.add('hidden');
            });
            
            if (isPhishing && riskLevel.includes('High')) {
                const dangerElement = recommendationsContent.querySelector('.danger');
                if (dangerElement) dangerElement.classList.remove('hidden');
            } else if (isPhishing || scoreValue > 30) {
                const warningElement = recommendationsContent.querySelector('.warning');
                if (warningElement) warningElement.classList.remove('hidden');
            } else {
                const safeElement = recommendationsContent.querySelector('.safe');
                if (safeElement) safeElement.classList.remove('hidden');
            }
        }
        
        // Populate detailed report
        populateDetailedReport(analysis);
    }
    
    // Populate the detailed report with analysis data
    function populateDetailedReport(analysis) {
        if (!analysis) return;
        
        // URL features
        if (urlFeatures) {
            const features = analysis.rule_based?.url_features || {};
            let featuresHtml = '<ul>';
            for (const [key, value] of Object.entries(features)) {
                if (typeof value !== 'object') {
                    featuresHtml += `<li><strong>${key}</strong>: ${value}</li>`;
                }
            }
            featuresHtml += '</ul>';
            urlFeatures.innerHTML = featuresHtml;
        }
        
        // Rule-based analysis
        if (ruleAnalysis) {
            const ruleBasedHtml = `
                <p><strong>Is Phishing</strong>: ${analysis.rule_based?.is_phishing ? 'Yes' : 'No'}</p>
                <p><strong>Risk Level</strong>: ${analysis.rule_based?.risk_level || 'N/A'}</p>
                <p><strong>Score</strong>: ${analysis.rule_based?.score || '0'}</p>
                <p><strong>Reasons</strong>:</p>
                <ul>
                    ${(analysis.rule_based?.reasons || []).map(reason => `<li>${reason}</li>`).join('')}
                </ul>
            `;
            ruleAnalysis.innerHTML = ruleBasedHtml;
        }
        
        // Model prediction
        if (modelPrediction) {
            const modelBasedHtml = `
                <p><strong>Is Phishing</strong>: ${analysis.model_based?.is_phishing ? 'Yes' : 'No'}</p>
                <p><strong>Probability</strong>: ${(analysis.model_based?.probability ? (analysis.model_based.probability * 100).toFixed(2) : 0)}%</p>
                <p><strong>Confidence</strong>: ${analysis.model_based?.confidence || 'N/A'}</p>
                <p><strong>Model Consensus</strong>: ${analysis.model_based?.model_consensus ? 'Yes' : 'No'}</p>
            `;
            modelPrediction.innerHTML = modelBasedHtml;
        }
        
        // Full JSON details
        if (jsonDetails) {
            try {
                jsonDetails.textContent = JSON.stringify(analysis, null, 2);
            } catch (e) {
                jsonDetails.textContent = "Error displaying JSON data";
            }
        }
    }
    
    // Reset UI to initial state
    function resetUI() {
        selectedFile = null;
        lastAnalysisResults = null;
        
        filenameDisplay.textContent = '';
        scanBtn.disabled = true;
        urlInput.value = '';
        
        resultsSection.classList.add('hidden');
        detailedReport.style.display = 'none';
    }
    
    // Initialize UI
    resetUI();
}); 