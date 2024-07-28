package com.app.pojo;

import jakarta.persistence.*;

import java.sql.Timestamp;

import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(name = "notice_details")
public class Notice {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY,generator = "notice_seq")
    @SequenceGenerator(name = "notice_seq", sequenceName ="notice_seq", allocationSize = 1)
	@Column(name = "notice_id")
	private int noticeId;

	@Column(name = "notice_summary")
	private String noticeSummary;

	@Column(name = "notice_details")
	private String noticeDetails;

	@Column(name = "notic_beg_dt")
	private Timestamp noticBegDt;
	
	@Column(name = "notic_end_dt")
	private Timestamp noticEndDt;
	
	@Column(name = "create_dt")
	private Timestamp createDt;
	
	@Column(name = "update_dt")
	private Timestamp updateDt;

	public int getNoticeId() {
		return noticeId;
	}

	public void setNoticeId(int noticeId) {
		this.noticeId = noticeId;
	}

	public String getNoticeSummary() {
		return noticeSummary;
	}

	public void setNoticeSummary(String noticeSummary) {
		this.noticeSummary = noticeSummary;
	}

	public String getNoticeDetails() {
		return noticeDetails;
	}

	public void setNoticeDetails(String noticeDetails) {
		this.noticeDetails = noticeDetails;
	}

	public Timestamp getNoticBegDt() {
		return noticBegDt;
	}

	public void setNoticBegDt(Timestamp noticBegDt) {
		this.noticBegDt = noticBegDt;
	}

	public Timestamp getNoticEndDt() {
		return noticEndDt;
	}

	public void setNoticEndDt(Timestamp noticEndDt) {
		this.noticEndDt = noticEndDt;
	}

	public Timestamp getCreateDt() {
		return createDt;
	}

	public void setCreateDt(Timestamp createDt) {
		this.createDt = createDt;
	}

	public Timestamp getUpdateDt() {
		return updateDt;
	}

	public void setUpdateDt(Timestamp updateDt) {
		this.updateDt = updateDt;
	}	
}
