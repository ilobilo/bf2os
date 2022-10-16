project('bf2os', 'cpp',
    version : 'v0.1',
    default_options : ['cpp_std=c++20']
)

fs = import('fs')
if fs.is_dir('limine')
    run_command('make', '-C', 'limine', capture : false, check : false)
endif

sources = [
    'src/main.cpp',
]

includes = include_directories('src')
conflict_dep = dependency('conflict')

executable('bf2os',
    dependencies : [conflict_dep],
    sources : sources,
    include_directories : includes
)