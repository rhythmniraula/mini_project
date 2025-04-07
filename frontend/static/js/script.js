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
    const loadingSection = document.getElementById('loading');
    const resultsSection = document.getElementById('results');
    const visitBtn = document.getElementById('visit-btn');
    const detailedReport = document.getElementById('detailed-report');
    const closeReportBtn = document.getElementById('close-report-btn');
    
    // Result display elements
    const qrImage = document.getElementById('qr-image');
    const qrContent = document.getElementById('qr-content');
    const qrType = document.getElementById('qr-type');
    const riskScore = document.getElementById('risk-score');
    const riskStatus = document.getElementById('risk-status');
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
        formData.append('file', file);
        formData.append('check_content', true);
        
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
    
    // Display analysis results
    function displayResults(data) {
        // Hide loading indicator
        if (loadingSection) {
            loadingSection.classList.add('hidden');
        }
        
        // Check for error
        if (data.status !== 'success') {
            alert('Error: ' + (data.message || 'Unknown error'));
            return;
        }
        
        // Extract QR code data from the analysis
        if (data.analysis && data.analysis.length > 0) {
            // For now, just use the first QR code found
            const firstQR = data.analysis[0];
            
            // If multiple QR codes found, show an info message
            if (data.analysis.length > 1) {
                const multipleQRMessage = document.createElement('div');
                multipleQRMessage.className = 'info-message';
                multipleQRMessage.textContent = `Multiple QR codes detected (${data.analysis.length}). Showing analysis for the first one.`;
                
                const resultsHeader = document.querySelector('#results .results-header');
                if (resultsHeader) {
                    // Remove any previous messages
                    const previousMessage = resultsHeader.querySelector('.info-message');
                    if (previousMessage) {
                        previousMessage.remove();
                    }
                    
                    resultsHeader.appendChild(multipleQRMessage);
                }
            }
            
            // Display QR content
            if (qrContent) {
                qrContent.textContent = firstQR.qr_data || 'No content detected';
            }
            
            // Display QR type
            if (qrType) {
                qrType.textContent = firstQR.qr_type || 'Unknown';
            }
            
            // Display QR image if available
            if (qrImage) {
                if (firstQR.visualized_image_base64) {
                    qrImage.src = firstQR.visualized_image_base64;
                } else if (firstQR.visualized_image) {
                    qrImage.src = `/results/${firstQR.visualized_image}`;
                }
            }
            
            // Check if it has phishing analysis
            if (firstQR.phishing_analysis) {
                const analysis = firstQR.phishing_analysis;
                
                // Display phishing analysis
                displayPhishingAnalysis(analysis);
                
                // Set up visit button if it's a URL
                if (visitBtn && analysis.url) {
                    visitBtn.classList.remove('hidden');
                    visitBtn.onclick = function() {
                        if (confirm('Are you sure you want to visit this URL? It may be unsafe.')) {
                            window.open(analysis.url, '_blank');
                        }
                    };
                } else if (visitBtn) {
                    visitBtn.classList.add('hidden');
                }
            } else {
                // Display "not a URL" message
                if (riskStatus) {
                    riskStatus.textContent = 'Not a URL';
                    riskStatus.style.backgroundColor = 'var(--info-color)';
                }
                
                // Clear risk factors
                if (riskFactors) {
                    riskFactors.innerHTML = '<li class="placeholder">Not applicable - QR code does not contain a URL</li>';
                }
                
                // Clear recommendations
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
        } else {
            alert('No QR code detected in the image.');
        }
    }
    
    // Display phishing analysis results
    function displayPhishingAnalysis(analysis) {
        if (!analysis || !analysis.final_assessment) {
            console.error("Invalid analysis data", analysis);
            return;
        }
        
        const finalAssessment = analysis.final_assessment;
        const isPhishing = finalAssessment.is_phishing;
        const riskLevel = finalAssessment.risk_level;
        const confidenceScore = finalAssessment.confidence_score;
        
        // Calculate and display risk score
        let scoreValue = 0;
        if (finalAssessment.probability) {
            scoreValue = Math.round(finalAssessment.probability * 100);
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
        
        // Display risk factors
        if (riskFactors) {
            const factors = finalAssessment.risk_factors || [];
            if (factors.length > 0) {
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
            if (confidenceScore !== undefined && confidenceScore !== null) {
                // Format as percentage with 2 decimal places
                const confidencePercent = (confidenceScore * 100).toFixed(2);
                modelConfidence.textContent = `${confidencePercent}%`;
            } else {
                modelConfidence.textContent = 'N/A';
            }
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
            const features = analysis.url_features || {};
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
            const ruleData = analysis.rule_analysis || {};
            const ruleBasedHtml = `
                <p><strong>Is Phishing</strong>: ${ruleData.is_phishing ? 'Yes' : 'No'}</p>
                <p><strong>Risk Level</strong>: ${ruleData.risk_level || 'N/A'}</p>
                <p><strong>Score</strong>: ${ruleData.score || '0'}</p>
                <p><strong>Reasons</strong>:</p>
                <ul>
                    ${(ruleData.reasons || []).map(reason => `<li>${reason}</li>`).join('')}
                </ul>
            `;
            ruleAnalysis.innerHTML = ruleBasedHtml;
        }
        
        // Model prediction
        if (modelPrediction) {
            const modelData = analysis.model_prediction || {};
            const modelBasedHtml = `
                <p><strong>Is Phishing</strong>: ${modelData.prediction === 1 ? 'Yes' : 'No'}</p>
                <p><strong>Probability</strong>: ${(modelData.probability ? (modelData.probability * 100).toFixed(2) : 0)}%</p>
                <p><strong>Confidence</strong>: ${(modelData.confidence ? (modelData.confidence * 100).toFixed(2) : 0)}%</p>
                <p><strong>Model Used</strong>: ${modelData.model_used || 'N/A'}</p>
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

    // Reset UI to initial state - only used for initialization now
    function resetUI() {
        selectedFile = null;
        lastAnalysisResults = null;
        
        if (filenameDisplay) filenameDisplay.textContent = '';
        if (scanBtn) scanBtn.disabled = true;
        
        if (resultsSection) resultsSection.classList.add('hidden');
        if (detailedReport) detailedReport.style.display = 'none';
    }

    // Initialize UI
    resetUI();
}); 