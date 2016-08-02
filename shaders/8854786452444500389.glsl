// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/color_v.cg
#version 330 core

uniform mat4 wvp;
in vec3 aPosition;
in vec4 aColor;

out vec4 vPosition;
out vec4 vColor;

void main()
{
    vPosition = vec4(aPosition, 1) * wvp;
    vColor = aColor;
}
