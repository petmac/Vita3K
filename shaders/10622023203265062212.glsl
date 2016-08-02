// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/clear_f.cg
#version 330 core

uniform vec4 uClearColor;

out vec4 fragColor;

void main()
{
    fragColor = uClearColor;
}
