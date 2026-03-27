# jinja_wrapper.py
from jinja2 import Environment, FileSystemLoader

def create_jinja_env(template_dir="templates"):
    env = Environment(loader=FileSystemLoader(template_dir))
    return env

def render_component(env, template_name, **context):
    template = env.get_template(template_name)
    return template.render(**context)   