// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/texture_v.cg
uniform mat4 wvp;
attribute vec3 aPosition;
attribute vec2 aTexcoord;

varying vec4 vPosition;
varying vec2 vTexcoord;

void main()
{
    vPosition = vec4(aPosition, 1) * wvp;
    vTexcoord = aTexcoord;
}
