// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/texture_v.cg
#version 330 core

uniform mat4 wvp;
in vec3 aPosition;
in vec2 aTexcoord;

out vec4 vPosition;
out vec2 vTexcoord;

void main()
{
    vPosition = vec4(aPosition, 1) * wvp;
    vTexcoord = aTexcoord;
}
