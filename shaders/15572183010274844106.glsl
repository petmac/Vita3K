// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/color_f.cg
#version 330 core

in vec4 vColor;

out vec4 fragColor;

void main()
{
    fragColor = vColor;
}
