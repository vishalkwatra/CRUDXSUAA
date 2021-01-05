package com.ey.hr.lms.code.businesslogic;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.springframework.stereotype.Component;

import com.ey.hr.lms.code.entities.Student;

import argo.jdom.JdomParser;
import argo.jdom.JsonNode;
import argo.saj.InvalidSyntaxException;

@Component
public class StudentOperation {

	public Connection conn;
	public Statement stmt;
	public ResultSet rs;

	String url;
	String user;
	String password;

	@PostConstruct
	public void startConnection() throws SQLException {

		this.url = "";
		this.user = "";
		this.password = "";

		try {
			String vcap_service = System.getenv("VCAP_SERVICES");

			if (vcap_service != null && vcap_service.length() > 0) {
				System.out.println("VCAP found");
				JsonNode root = new JdomParser().parse(vcap_service);
				JsonNode serviceRoot = root.getNode("hanatrial");
				JsonNode serviceCreden = serviceRoot.getNode(0).getNode("credentials");
				this.url = serviceCreden.getStringValue("url");
				this.user = serviceCreden.getStringValue("user");
				this.password = serviceCreden.getStringValue("password");
			} else {
				System.out.println("VAP error!");
			}

		} catch (InvalidSyntaxException e1) {
//			e1.printStackTrace();
			System.out.println("Error in getting vcap services");
		}

//		String url = "jdbc:sap://zeus.hana.prod.eu-central-1.whitney.dbaas.ondemand.com:23803?encrypt=true&validateCertificate=true&currentschema=21F405B7E6814B2DB3A7283339AF40ED";
//		String username = "21F405B7E6814B2DB3A7283339AF40ED_05F07G6XHR6KLBB4QT6L3WHKH_RT";
//		String password = "Vj60JfNbiyCKqgXSATawI8tCCav5JHocWD4iAerWomG6n9Zx0NMYQESqFc0ET62OlKASno9pkUlAWU1p_m_zS3pJZ7-08DZPl8iFfIVe9G.SwMA0MpUWVgp5vA4sR1Bn";

//		String url = this.url;
//		String username = this.user;
//		String password = this.password;

		try {
			conn = DriverManager.getConnection(this.url, this.user, this.password);
			stmt = conn.createStatement();
		} catch (SQLException e) {
			System.out.println("!!Error in DB Conn!!");
			System.out.println(e.getMessage());
		}
	}

	public List<Student> giveAllStudent() throws SQLException {
		List<Student> studentList = new ArrayList<Student>();
		rs = stmt.executeQuery("select top 100 * from student");
		while (rs.next()) {
			studentList.add(new Student(rs.getInt("ID"), rs.getString("FIRSTNAME"), rs.getString("LASTNAME"),
					rs.getString("LOCATION_STUDENT")));
		}
		return studentList;
	}

	public Student giveStudent(int id) throws SQLException {
		Student studentobj = new Student(0, null, null, null);
		rs = stmt.executeQuery("select * from student where id=" + "'" + Integer.toString(id) + "'");
		while (rs.next()) {
			studentobj.id = rs.getInt("ID");
			studentobj.firstName = rs.getString("FIRSTNAME");
			studentobj.lastName = rs.getString("LASTNAME");
			studentobj.locationStudent = rs.getString("LOCATION_STUDENT");
		}
		return studentobj;
	}

	@PreDestroy
	public void endConnection() throws SQLException {
		rs.close();
		stmt.close();
		conn.close();
	}
}
