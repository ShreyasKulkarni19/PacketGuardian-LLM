// Add file name display functionality
document.getElementById("pcapFile").addEventListener("change", function () {
  const fileName = this.files[0] ? this.files[0].name : "No file selected";
  document.getElementById("file-name").textContent = fileName;
});

document.getElementById("uploadForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const fileInput = document.getElementById("pcapFile");
  const resultDiv = document.getElementById("result");

  if (!fileInput.files.length) {
    resultDiv.innerHTML = '<p style="color: red;">Please select a file.</p>';
    return;
  }

  const file = fileInput.files[0];
  if (!file.name.endsWith(".pcap")) {
    resultDiv.innerHTML =
      '<p style="color: red;">Only .pcap files are allowed.</p>';
    return;
  }

  const formData = new FormData();
  formData.append("pcapFile", file);

  try {
    // Initialize progress display
    resultDiv.innerHTML = `
      <div class="progress-container">
        <h3>Processing File: ${file.name}</h3>
        <div class="progress-bar-container">
          <div id="progress-bar" class="progress-bar"></div>
        </div>
        <div id="progress-message">Starting analysis...</div>
        <div id="progress-steps" class="progress-steps">
          <div class="step active">
            <div class="step-number">1</div>
            <div class="step-label">Upload</div>
          </div>
          <div class="step">
            <div class="step-number">2</div>
            <div class="step-label">Scan</div>
          </div>
          <div class="step">
            <div class="step-number">3</div>
            <div class="step-label">Chunk</div>
          </div>
          <div class="step">
            <div class="step-number">4</div>
            <div class="step-label">AI Analysis</div>
          </div>
          <div class="step">
            <div class="step-number">5</div>
            <div class="step-label">Report</div>
          </div>
        </div>
        <div id="log-container" class="log-container">
          <div class="log-heading">Processing Log</div>
          <div id="processing-log" class="processing-log"></div>
        </div>
      </div>`;

    const progressBar = document.getElementById("progress-bar");
    const progressMessage = document.getElementById("progress-message");
    const processingLog = document.getElementById("processing-log");
    const progressSteps = document
      .getElementById("progress-steps")
      .querySelectorAll(".step");

    // Submit file and get analysis ID
    const response = await fetch("http://localhost:8080/upload", {
      method: "POST",
      body: formData,
      timeout: 60000,
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || "Unknown server error");
    }

    const initialData = await response.json();
    const analysisID = initialData.analysisID;

    // Update upload step as complete
    progressSteps[0].classList.add("completed");

    // Add initial log message
    processingLog.innerHTML += `<div class="log-entry"><span class="timestamp">${formatTime(
      new Date()
    )}</span><span class="message">Upload complete. Starting packet analysis...</span></div>`;
    progressSteps[1].classList.add("active"); // Activate scan step

    // Poll for progress updates
    let processingComplete = false;
    let progressPercentage = 20; // Start at 20% after initial upload
    let lastUpdateCount = 0;

    while (!processingComplete) {
      await new Promise((resolve) => setTimeout(resolve, 1000)); // Poll every second

      const progressResponse = await fetch(
        `http://localhost:8080/progress?id=${analysisID}`
      );
      if (!progressResponse.ok) {
        throw new Error("Failed to fetch progress updates");
      }

      const progressData = await progressResponse.json();

      // Update progress bar
      if (progressData.status === "complete") {
        progressPercentage = 100;
        processingComplete = true;
      } else {
        // Incrementally increase progress bar based on steps completed
        const totalUpdates = progressData.progressUpdates.length;
        if (totalUpdates > lastUpdateCount) {
          // Add new log entries
          for (let i = lastUpdateCount; i < totalUpdates; i++) {
            processingLog.innerHTML += `<div class="log-entry"><span class="timestamp">${formatTime(
              new Date()
            )}</span><span class="message">${
              progressData.progressUpdates[i]
            }</span></div>`;
            processingLog.scrollTop = processingLog.scrollHeight; // Auto-scroll to bottom

            // Update active step based on log content
            const updateText = progressData.progressUpdates[i].toLowerCase();
            if (updateText.includes("scan") || updateText.includes("packet")) {
              progressSteps[1].classList.add("active"); // Scan step
            } else if (
              updateText.includes("chunk") ||
              updateText.includes("split")
            ) {
              progressSteps[1].classList.add("completed");
              progressSteps[2].classList.add("active"); // Chunk step
            } else if (
              updateText.includes("openai") ||
              updateText.includes("analysis")
            ) {
              progressSteps[2].classList.add("completed");
              progressSteps[3].classList.add("active"); // AI Analysis step
            } else if (
              updateText.includes("complete") ||
              updateText.includes("report")
            ) {
              progressSteps[3].classList.add("completed");
              progressSteps[4].classList.add("active"); // Report step
            }
          }

          lastUpdateCount = totalUpdates;

          // Calculate progress percentage (cap at 95% until complete)
          if (progressPercentage < 95) {
            progressPercentage = 20 + Math.min(75, (totalUpdates / 15) * 75);
          }
        }
      }

      // Update UI elements
      progressBar.style.width = `${progressPercentage}%`;
      progressMessage.textContent =
        progressData.progressUpdates[progressData.progressUpdates.length - 1] ||
        "Processing...";

      // If processing is complete, show the results
      if (processingComplete) {
        // Mark all steps as completed
        progressSteps.forEach((step) => step.classList.add("completed"));

        // Update log
        processingLog.innerHTML += `<div class="log-entry"><span class="timestamp">${formatTime(
          new Date()
        )}</span><span class="message">Processing complete! Generating results...</span></div>`;

        // Wait a moment for visual effect
        await new Promise((resolve) => setTimeout(resolve, 1000));

        // Display results
        displayResults(progressData, analysisID);
        break;
      }
    }
  } catch (err) {
    resultDiv.innerHTML = `<p style="color: red;">Error: ${err.message}</p>`;
    console.error("Error details:", err);
  }
});

// Helper function to format time as HH:MM:SS
function formatTime(date) {
  return date.toTimeString().split(" ")[0];
}

// Function to display final results
function displayResults(data, analysisID) {
  const resultDiv = document.getElementById("result");

  // Format the result based on whether threats were detected
  if (data.threatsDetected) {
    // Create HTML to display threat summary and download button
    let resultsHTML = `
      <div class="results-container">
        <h2>Analysis Results</h2>
        <p><strong>Status:</strong> <span class="alert">Threats Detected</span></p>
        <p><strong>Packets Processed:</strong> ${data.packetCount}</p>
        
        <div class="summary-section">
          <h3>Summary of Findings:</h3>
          <div class="summary-item">
            <p><strong>Issue:</strong> ${data.summary.issue}</p>
          </div>
          <div class="summary-item">
            <p><strong>Location:</strong> ${data.summary.location}</p>
          </div>
          <div class="summary-item">
            <p><strong>Cause:</strong> ${data.summary.cause}</p>
          </div>
          <div class="summary-item">
            <p><strong>Recommended Solution:</strong> ${data.summary.solution}</p>
          </div>
        </div>
        
        <div class="threats-section">
          <h3>Detected Threats:</h3>
          <ul class="threats-list">
    `;

    // Add each threat to the list
    data.threats.forEach((threat) => {
      resultsHTML += `<li>${threat}</li>`;
    });

    resultsHTML += `
          </ul>
        </div>
        
        <div class="processing-details-section">
          <h3>Processing Details:</h3>
          <div class="processing-summary">
            <p><strong>Steps Completed:</strong></p>
            <ol class="processing-steps">
    `;

    // Add processing steps
    data.progressUpdates.forEach((update) => {
      resultsHTML += `<li>${update}</li>`;
    });

    resultsHTML += `
            </ol>
          </div>
        </div>
        
        <div class="download-section">
          <p>For a detailed analysis of each packet chunk, download the complete report.</p>
          <button id="downloadReport" class="download-btn" data-analysis-id="${analysisID}">Download Detailed Report</button>
        </div>
      </div>
    `;

    resultDiv.innerHTML = resultsHTML;

    // Add event listener for download button
    document
      .getElementById("downloadReport")
      .addEventListener("click", function () {
        const analysisID = this.getAttribute("data-analysis-id");
        window.open(
          `http://localhost:8080/download-report?id=${analysisID}`,
          "_blank"
        );
      });
  } else {
    // No threats detected
    resultDiv.innerHTML = `
      <div class="results-container">
        <h2>Analysis Results</h2>
        <p><strong>Status:</strong> <span class="success">No Threats Detected</span></p>
        <p><strong>Packets Processed:</strong> ${data.packetCount}</p>
        <p class="no-threats">No security threats were identified in the uploaded PCAP file.</p>
        
        <div class="processing-details-section">
          <h3>Processing Details:</h3>
          <div class="processing-summary">
            <p><strong>Steps Completed:</strong></p>
            <ol class="processing-steps">
    `;

    // Add processing steps
    data.progressUpdates.forEach((update) => {
      resultDiv.innerHTML += `<li>${update}</li>`;
    });

    resultDiv.innerHTML += `
            </ol>
          </div>
        </div>
      </div>
    `;
  }
}
