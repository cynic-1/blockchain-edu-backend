package docker

import (
	"context"
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/config"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

type DockerManager struct {
	client *client.Client
}

func NewDockerManager() (*DockerManager, error) {
	cli, err := client.NewClientWithOpts(client.WithVersion("1.41"))
	if err != nil {
		return nil, err
	}
	return &DockerManager{client: cli}, nil
}

func (dm *DockerManager) CreateContainer(userID string, port int) (string, error) {
	ctx := context.Background()
	resp, err := dm.client.ContainerCreate(ctx, &container.Config{
		Image: config.AppConfig.Docker.Image,
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

	return resp.ID, nil
}

func (dm *DockerManager) StartContainer(ctx context.Context, containerID string) error {
	return dm.client.ContainerStart(ctx, containerID, container.StartOptions{})
}

func (dm *DockerManager) StopContainer(ctx context.Context, containerID string) error {
	stopOptions := container.StopOptions{}
	return dm.client.ContainerStop(ctx, containerID, stopOptions)
}

func (dm *DockerManager) RemoveContainer(ctx context.Context, containerID string) error {
	removeOptions := container.RemoveOptions{
		Force: true,
	}
	return dm.client.ContainerRemove(ctx, containerID, removeOptions)
}
