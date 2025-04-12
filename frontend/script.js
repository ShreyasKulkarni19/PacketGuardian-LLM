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
    resultDiv.innerHTML = "<p>Uploading...</p>";

    const response = await fetch("http://localhost:8080/upload", {
      method: "POST",
      body: formData,
    });

    const data = await response.json();

    if (response.ok) {
      resultDiv.innerHTML = `<p style="color: green;">Upload successful! Result: ${data.result}</p>`;
    } else {
      resultDiv.innerHTML = `<p style="color: red;">Error: ${
        data.error || "Upload failed"
      }</p>`;
    }
  } catch (err) {
    resultDiv.innerHTML =
      '<p style="color: red;">Error: Unable to connect to server</p>';
  }
});
