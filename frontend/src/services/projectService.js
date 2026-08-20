import api from "./api";

export const getProjects = async () => {
  const response = await api.get("/api/projects/");
  return response.data;
};

export const createProject = async (projectData) => {
  const response = await api.post("/api/projects/", projectData);
  return response.data;
};

export const getProject = async (projectId) => {
  const response = await api.get(`/api/projects/${projectId}`);
  return response.data;
};
