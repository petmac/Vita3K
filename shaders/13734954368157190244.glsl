// https://github.com/xerpi/libvita2d/blob/master/libvita2d/shader/texture_tint_f.cg
#version 330 core

uniform sampler2D tex;
uniform vec4 uTintColor;
in vec2 vTexcoord;

out vec4 fragColor;

void main()
{
    fragColor = texture(tex, vTexcoord) * uTintColor;
}
