"""WTForms definitions for the victim application."""

from decimal import Decimal

from flask_wtf import FlaskForm
from wtforms import DecimalField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import AnyOf, DataRequired, Email, Length, NumberRange


class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired(), Length(max=40)])
    password = PasswordField("密码", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("登录")


class LogoutForm(FlaskForm):
    submit = SubmitField("退出登录")


class ProfileForm(FlaskForm):
    email = StringField("邮箱", validators=[DataRequired(), Email(), Length(max=255)])
    submit = SubmitField("保存邮箱")


class TransferForm(FlaskForm):
    recipient_username = StringField("收款账户", validators=[DataRequired(), Length(min=1, max=40)])
    amount = DecimalField(
        "金额",
        places=2,
        rounding=None,
        validators=[DataRequired(), NumberRange(min=Decimal("0.01"), max=Decimal("10000"))],
    )
    note = StringField("备注", validators=[Length(max=200)])
    submit = SubmitField("确认转账")


class GrantForm(FlaskForm):
    client_name = SelectField(
        "应用",
        choices=[
            ("Calendar Demo", "Calendar Demo"),
            ("Photo Printer", "Photo Printer"),
            ("Research Dashboard", "Research Dashboard"),
        ],
        validators=[DataRequired()],
    )
    scope = SelectField(
        "权限范围",
        choices=[
            ("profile:read", "读取个人资料"),
            ("transactions:read", "读取交易记录"),
            ("profile:read transactions:read", "读取资料和交易记录"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("授予权限")


class RevokeGrantForm(FlaskForm):
    submit = SubmitField("撤销")


class DeleteDataForm(FlaskForm):
    confirmation = StringField(
        "输入 DELETE 确认",
        validators=[DataRequired(), AnyOf(["DELETE"], message="请输入 DELETE。")],
    )
    submit = SubmitField("删除实验活动数据")


class QuickTransferForm(FlaskForm):
    submit = SubmitField("确认转账")


class QuickGrantForm(FlaskForm):
    submit = SubmitField("确认授权")


class QuickReauthForm(FlaskForm):
    password = PasswordField("密码", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("重新验证")
