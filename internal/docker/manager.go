package docker

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/yourusername/blockchain-edu-backend/internal/config"
)

type DockerManager struct {
	client *client.Client
}

func NewDockerManager() (*DockerManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &DockerManager{client: cli}, nil
}

func (dm *DockerManager) CreateContainer(userID string, port int) (string, error) {
	ctx := context.Background()
	resp, err := dm.client.ContainerCreate(ctx, &container.Config{
		Image: config.AppConfig.DockerImage,
	}, &container.HostConfig{
		PortBindings: nat.PortMap{
			"8080/tcp": []nat.PortBinding{
				{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", port)},
			},
		},
	}, nil, nil, userID)
	if err != nil {
		return "", err
	}

	if err := dm.client.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}

	return resp.ID, nil
}

func (dm *DockerManager) RemoveContainer(containerID string) error {
	ctx := context.Background()
	return dm.client.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
}
