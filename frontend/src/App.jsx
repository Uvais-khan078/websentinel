import { useEffect, useState } from "react";
import { getProjects } from "./services/projectService";

function App() {
  const [projects, setProjects] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadProjects = async () => {
      try {
        const data = await getProjects();
        setProjects(data);
      } catch (err) {
        console.error(err);
        setError("Could not connect to WebSentinel API");
      }
    };

    loadProjects();
  }, []);

  return (
    <div>
      <h1>WebSentinel</h1>

      <p>AI-Assisted Web Application Penetration Testing Platform</p>

      <h2>Projects</h2>

      {error && <p>{error}</p>}

      {projects.length === 0 ? (
        <p>No projects found.</p>
      ) : (
        projects.map((project) => (
          <div key={project.id}>
            <h3>{project.name}</h3>
            <p>{project.target_url}</p>
          </div>
        ))
      )}
    </div>
  );
}

export default App;