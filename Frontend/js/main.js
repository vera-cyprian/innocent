document.addEventListener("DOMContentLoaded", () => {
    const categorySelect = document.getElementById("categorySelect");
    const caseGrid = document.getElementById("caseGrid");
  
    const fetchCases = async () => {
      const res = await fetch("http://localhost:5000/api/cases");
      return await res.json();
    };
  
    const renderCases = (cases) => {
      caseGrid.innerHTML = cases.map(c => `
        <div class="case">
          <h3>${c.category} Law</h3>
          <p><strong>Date:</strong> ${c.date} &nbsp; <strong>Time:</strong> ${c.time}</p>
          ${c.imagePath ? `<img src="http://localhost:5000/uploads/${c.imagePath}" alt="case image" />` : ''}
          <p>${c.content}</p>
        </div>
      `).join("");
    };
  
    const loadAndFilterCases = async () => {
      const cases = await fetchCases();
      const selected = categorySelect.value;
      const filtered = selected === "All" ? cases : cases.filter(c => c.category === selected);
      renderCases(filtered);
    };
  
    categorySelect.addEventListener("change", loadAndFilterCases);
    loadAndFilterCases();
  });
  