// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/color_v.cg
uniform mat4 wvp;
attribute vec3 aPosition;
attribute vec4 aColor;

varying vec4 vPosition;
varying vec4 vColor;

void main()
{
    vPosition = vec4(aPosition, 1) * wvp;
    vColor = aColor;
}
